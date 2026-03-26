---
title: Architecture
description: How Zoomies layers compose — from packets to HTTP/3.
weight: 10
---

## Layer stack

Zoomies is built as composable layers. Each layer is independently testable.

```
┌─────────────────────────┐
│       H3Connection      │  HTTP/3 state machine
├─────────────────────────┤
│      QuicConnection     │  QUIC state machine + recovery
├────────┬────────────────┤
│ Stream │    Recovery     │  Reassembly + loss detection
├────────┼────────────────┤
│ Crypto │     Frames     │  TLS 1.3 + frame encode/decode
├────────┴────────────────┤
│    Packet / Encoding    │  Wire format + variable-length integers
└─────────────────────────┘
```

## Package structure

| Package | Responsibility |
|---------|---------------|
| `zoomies.encoding` | Buffer, varint, byte utilities |
| `zoomies.packet` | QUIC packet headers, builder, transport params |
| `zoomies.frames` | Frame types: ACK, CRYPTO, STREAM, etc. |
| `zoomies.crypto` | TLS 1.3 handshake, HKDF, packet protection |
| `zoomies.core` | `QuicConnection`, `QuicConfiguration`, stream management |
| `zoomies.recovery` | Loss detection, RTT, congestion control (RFC 9002) |
| `zoomies.h3` | `H3Connection`, QPACK encode/decode |
| `zoomies.events` | All event dataclasses |
| `zoomies.primitives` | Shared types and constants |
| `zoomies.contracts` | Protocol interfaces (key derivation, etc.) |

## Data flow

```
datagram in
  → pull_quic_header()
  → decrypt (CryptoContext)
  → parse frames
  → update connection state
  → emit QuicEvent(s)
  → QuicEvent → H3Connection.handle_event() → H3Event

outbound:
  → H3Connection.send_headers() / send_data()
  → QuicConnection builds frames
  → encrypt + build packet
  → send_datagrams() → bytes out
```

## Design principles

1. **Sans-I/O** — No sockets, no async, no threads inside the library
2. **Types as contracts** — Frozen dataclasses for events, Protocol classes for interfaces
3. **Zero shared mutable state** — Each connection is independent
4. **Minimal dependencies** — Only `cryptography` for TLS primitives
