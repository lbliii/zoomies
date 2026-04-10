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
| `final_size` | `int` | Final byte offset of the stream |

### StopSendingReceived

Emitted when the peer requests that you stop sending on a stream (`STOP_SENDING` frame).

| Field | Type | Description |
|-------|------|-------------|
| `stream_id` | `int` | QUIC stream identifier |
| `error_code` | `int` | Application error code |

### ConnectionClosed

Emitted when the connection closes (peer `CONNECTION_CLOSE` or idle timeout).

| Field | Type | Description |
|-------|------|-------------|
| `error_code` | `int` | Transport or application error code |
| `reason` | `str \| None` | Optional human-readable reason phrase |

### DatagramReceived

Emitted for QUIC DATAGRAM frames (unreliable delivery).

| Field | Type | Description |
|-------|------|-------------|
| `data` | `bytes` | Datagram payload |

### ZeroRttAccepted

Emitted on the client when the server accepts 0-RTT early data. Application data sent before the handshake completed was processed by the server.

```python
@dataclass(frozen=True)
class ZeroRttAccepted(QuicEvent): ...
```

### ZeroRttRejected

Emitted on the client when the server rejects 0-RTT early data. Zoomies automatically resends affected streams as 1-RTT data — no application action required, but you may want to log or adjust behavior.

```python
@dataclass(frozen=True)
class ZeroRttRejected(QuicEvent): ...
```

## HTTP/3 Events

### H3HeadersReceived

Emitted when HTTP/3 headers are decoded from a request or response.

| Field | Type | Description |
|-------|------|-------------|
| `headers` | `list[tuple[bytes, bytes]]` | Decoded QPACK headers |
| `stream_id` | `int` | H3 stream identifier |
| `end_stream` | `bool` | `True` if no body follows |
| `is_0rtt` | `bool` | `True` if received via 0-RTT early data |

### H3DataReceived

Emitted when HTTP/3 body data arrives.

| Field | Type | Description |
|-------|------|-------------|
| `data` | `bytes` | Body payload |
| `stream_id` | `int` | H3 stream identifier |
