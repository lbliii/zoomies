"""Zoomies — Free-threading-native QUIC and HTTP/3 for Python 3.14t.

A sans-I/O protocol library for QUIC (RFC 9000) and HTTP/3 (RFC 9114).
Native to the b-stack (Pounce, Chirp); no b-stack deps. Usable anywhere. Built for free-threaded Python 3.14t.

**Public API:**

- `QuicConnection.datagram_received()`: Feed UDP datagrams in, get protocol events
- `QuicConnection.send_datagrams()`: Get outbound datagrams to transmit
- `H3Connection`: HTTP/3 connection state machine (handle_event, send_headers, send_data)
- Events: `HandshakeComplete`, `StreamDataReceived`, `H3HeadersReceived`, `H3DataReceived`

**Design Philosophy:**

1. **Sans-I/O**: Protocol layer consumes bytes, produces bytes. No socket access.
   The caller (e.g. an ASGI server, UDP loop, or custom I/O layer) owns I/O and feeds datagrams.

2. **Types as contracts**: Frozen dataclasses for events, Protocols for handlers.
   No `Any` in public APIs.

3. **Free-threading native**: No C extensions with limited API. Uses cryptography
   (3.14t-compatible) for TLS 1.3. Thread-safe by design.

4. **Composition**: Packet → Crypto → Stream → Connection → HTTP/3.
   Each layer testable in isolation.

**Architecture:**

    datagram in → QuicConnection.datagram_received() → QuicEvent
    QuicEvent → H3Connection.handle_event() → H3Event (HeadersReceived, DataReceived)
    H3Event → build_scope() → ASGI app

**Status:** Pre-alpha. API stable for sans-I/O integration. See docs/design/architecture.md.
"""

from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.events import (
    ConnectionClosed,
    DatagramReceived,
    H3DataReceived,
    H3HeadersReceived,
    HandshakeComplete,
    QuicEvent,
    StreamDataReceived,
)
from zoomies.h3 import H3Connection, H3StreamSender

__all__ = [
    "ConnectionClosed",
    "DatagramReceived",
    "H3Connection",
    "H3DataReceived",
    "H3HeadersReceived",
    "H3StreamSender",
    "HandshakeComplete",
    "QuicConfiguration",
    "QuicConnection",
    "QuicEvent",
    "StreamDataReceived",
]

__version__ = "0.1.0"
