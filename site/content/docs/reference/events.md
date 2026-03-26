---
title: Events
description: All event types emitted by QuicConnection and H3Connection.
weight: 10
---

## QUIC Events

All events are frozen dataclasses. They are the primary output of `QuicConnection.datagram_received()` and `QuicConnection.handle_timer()`.

### HandshakeComplete

Emitted when the TLS 1.3 handshake finishes and 1-RTT keys are available.

```python
@dataclass(frozen=True)
class HandshakeComplete(QuicEvent): ...
```

### StreamDataReceived

Emitted when ordered stream data is available.

| Field | Type | Description |
|-------|------|-------------|
| `stream_id` | `int` | QUIC stream identifier |
| `data` | `bytes` | Reassembled payload |
| `end_stream` | `bool` | `True` if FIN bit set |

### StreamReset

Emitted when the peer resets a stream via `RESET_STREAM` frame.

| Field | Type | Description |
|-------|------|-------------|
| `stream_id` | `int` | QUIC stream identifier |
| `error_code` | `int` | Application error code |

### ConnectionClosed

Emitted when the connection closes (peer `CONNECTION_CLOSE` or idle timeout).

### DatagramReceived

Emitted for QUIC DATAGRAM frames (unreliable delivery).

| Field | Type | Description |
|-------|------|-------------|
| `data` | `bytes` | Datagram payload |

## HTTP/3 Events

### H3HeadersReceived

Emitted when HTTP/3 headers are decoded from a request or response.

| Field | Type | Description |
|-------|------|-------------|
| `headers` | `list[Header]` | Decoded QPACK headers |
| `stream_id` | `int` | H3 stream identifier |

### H3DataReceived

Emitted when HTTP/3 body data arrives.

| Field | Type | Description |
|-------|------|-------------|
| `data` | `bytes` | Body payload |
| `stream_id` | `int` | H3 stream identifier |
