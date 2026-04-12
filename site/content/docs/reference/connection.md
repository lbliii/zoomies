---
title: QuicConnection
description: The core QUIC connection state machine.
weight: 30
---

## QuicConnection

The central API. A sans-I/O state machine that processes inbound datagrams and produces outbound datagrams and events.

```python
from zoomies.core import QuicConnection, QuicConfiguration

config = QuicConfiguration(certificate=cert, private_key=key)
conn = QuicConnection(config)
```

## Methods

### connect

Generate the Initial packet with ClientHello. Client mode only — call once after construction.

```python
conn.connect()
```

### datagram_received

Feed a UDP datagram into the connection. Returns a list of events.

```python
events: list[QuicEvent] = conn.datagram_received(data, addr, now=0.0)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | `bytes` | Raw UDP payload |
| `addr` | `tuple[str, int]` | Source address `(host, port)` |
| `now` | `float` | Current time (default `0.0`) |

### send_datagrams

Get outbound datagrams that the connection wants to send.

```python
datagrams: list[bytes] = conn.send_datagrams(now=0.0)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `now` | `float` | Current time (default `0.0`) |

### send_stream_data

Queue data for transmission on a stream. Stream IDs follow RFC 9000 §2.1: client-initiated bidirectional streams use IDs 0, 4, 8, 12, …

```python
conn.send_stream_data(stream_id, data, end_stream=False)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `stream_id` | `int` | QUIC stream identifier |
| `data` | `bytes` | Payload to send |
| `end_stream` | `bool` | Set `True` to send FIN (default `False`) |

### get_timer

Get the next timer deadline (absolute time). Returns `None` if no timer is pending.

```python
timeout: float | None = conn.get_timer()
```

### handle_timer

Process a timer expiry. Returns events (e.g., retransmission, PTO probe).

```python
events: list[QuicEvent] = conn.handle_timer(now)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `now` | `float` | Current time |

### close

Initiate graceful connection close.

```python
conn.close(error_code=0, reason="")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `error_code` | `int` | Transport or application error code (default `0`) |
| `reason` | `str` | Human-readable reason phrase (default `""`) |
