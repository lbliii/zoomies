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
| `is_0rtt` | `bool` | `True` if received via 0-RTT early data |

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
| `addr` | `tuple[str, int]` | Source address |

### ConnectionIdIssued

Emitted when a new connection ID is issued to the peer.

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | `bytes` | The new connection ID |
| `retire_prior_to` | `int` | Peer should retire CIDs below this sequence number |

### ConnectionIdRetired

Emitted when a connection ID is retired.

| Field | Type | Description |
|-------|------|-------------|
| `connection_id` | `bytes` | The retired connection ID |

### DecryptionFailed

Emitted when a packet cannot be decrypted (informational — not necessarily an error).

| Field | Type | Description |
|-------|------|-------------|
| `packet_type` | `str` | Type of the undecryptable packet |

### ZeroRttAccepted

Emitted on the client when the server accepts 0-RTT early data.

```python
@dataclass(frozen=True)
class ZeroRttAccepted: ...
```

### ZeroRttRejected

Emitted on the client when the server rejects 0-RTT early data. Zoomies automatically resends affected streams as 1-RTT — no application action required.

```python
@dataclass(frozen=True)
class ZeroRttRejected: ...
```

### NewSessionTicket

Emitted when the server issues a session ticket. Store the ticket for 0-RTT resumption on the next connection.

| Field | Type | Description |
|-------|------|-------------|
| `ticket` | `SessionTicket` | The session ticket to store |

### RetryReceived

Emitted on the client when a Retry packet is received from the server (stateless address validation).

| Field | Type | Description |
|-------|------|-------------|
| `retry_source_cid` | `bytes` | Source connection ID from the Retry packet |

### ConnectionMigrated

Emitted when a peer migrates to a new network address (RFC 9000 §9).

| Field | Type | Description |
|-------|------|-------------|
| `old_addr` | `tuple[str, int]` | Previous peer address |
| `new_addr` | `tuple[str, int]` | New peer address |

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
| `end_stream` | `bool` | `True` if this is the final DATA frame |
