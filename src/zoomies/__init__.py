"""Zoomies — Free-threading-native QUIC and HTTP/3 for Python 3.14t.

A sans-I/O protocol library for QUIC (RFC 9000) and HTTP/3 (RFC 9114).
Designed for Pounce and Chirp, built for free-threaded Python 3.14t.

**Public API (coming soon):**

- `receive_datagram()`: Feed UDP datagrams in, get protocol events out
- `datagrams_to_send()`: Get outbound datagrams to transmit
- `H3Connection`: HTTP/3 connection state machine (sans-I/O)

**Design Philosophy:**

1. **Sans-I/O**: Protocol layer consumes bytes, produces bytes. No socket access.
   The caller (e.g. Pounce's worker) owns I/O and feeds datagrams.

2. **Types as contracts**: Frozen dataclasses for events, Protocols for handlers.
   No `Any` in public APIs.

3. **Free-threading native**: No C extensions with limited API. Uses cryptography
   (3.14t-compatible) for TLS 1.3. Thread-safe by design.

4. **Composition**: Packet → Crypto → Stream → Connection → HTTP/3.
   Each layer testable in isolation.

**Architecture:**

    datagram in → QuicConnection.receive_datagram() → QuicEvent
    QuicEvent → H3Connection.handle_event() → H3Event (HeadersReceived, DataReceived)
    H3Event → build_scope() → ASGI app

**Status:** Pre-alpha. Scaffolding phase. See docs/design/architecture.md.
"""

__version__ = "0.1.0"
