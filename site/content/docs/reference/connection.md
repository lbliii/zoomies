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

### datagram_received

Feed a UDP datagram into the connection. Returns a list of events.

```python
events: list[QuicEvent] = conn.datagram_received(data: bytes, addr: tuple)
```

### send_datagrams

Get outbound datagrams that the connection wants to send.

```python
datagrams: list[bytes] = conn.send_datagrams()
```

### get_next_stream_id

Allocate the next available stream ID.

```python
stream_id: int = conn.get_next_stream_id()
```

### send_stream_data

Queue data for transmission on a stream.

```python
conn.send_stream_data(stream_id: int, data: bytes, end_stream: bool = False)
```

### get_timer

Get the next timer deadline (absolute time). Returns `None` if no timer is pending.

```python
timeout: float | None = conn.get_timer()
```

### handle_timer

Process a timer expiry. Returns events (e.g., retransmission, PTO probe).

```python
events: list[QuicEvent] = conn.handle_timer()
```

### close

Initiate connection close with an optional error code.

```python
conn.close(error_code: int = 0, reason_phrase: str = "")
```
