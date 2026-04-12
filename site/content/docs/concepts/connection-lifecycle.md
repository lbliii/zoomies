---
title: Connection Lifecycle
description: QUIC connection states — handshake, streams, loss recovery, and close.
weight: 20
---

## Overview

A QUIC connection progresses through well-defined states. Zoomies models each as events emitted from `QuicConnection`.

```
Initial → Handshake → 1-RTT (application data) → Close
                 ↑
   0-RTT ────────┘  (resumption with early data)
```

## Client connect

Clients initiate the handshake by calling `connect()`:

```python
from zoomies.core import QuicConnection, QuicConfiguration

client = QuicConnection(QuicConfiguration(is_client=True))
client.connect()

# Send the Initial packet
for dg in client.send_datagrams():
    sock.sendto(dg, server_addr)
```

## Handshake

The TLS 1.3 handshake runs inside QUIC CRYPTO frames. Zoomies handles:

1. **Initial packets** — Client Hello / Server Hello exchange
2. **Handshake packets** — Certificate, Finished messages
3. **HandshakeComplete event** — Keys derived, 1-RTT ready

```python
events = conn.datagram_received(datagram, addr)
for event in events:
    if isinstance(event, HandshakeComplete):
        # Connection is ready for application data
        ...
```

## 0-RTT early data

When a client reconnects with a session ticket from a previous connection, it can send application data in the very first flight — before the handshake completes.

```python
from zoomies.crypto.tls import SessionTicket

# Reconnect with a stored ticket
config = QuicConfiguration(is_client=True, session_ticket=stored_ticket)
client = QuicConnection(config)
client.connect()

# Send early data immediately — no waiting for HandshakeComplete
client.send_stream_data(stream_id, b"early request")
```

The server decides whether to accept or reject 0-RTT data using a `ZeroRttPolicy`:

```python
class MyPolicy:
    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        # Accept if ticket is fresh enough
        return True

config = QuicConfiguration(
    certificate=cert, private_key=key,
    zero_rtt_policy=MyPolicy(),
)
```

The client receives either a `ZeroRttAccepted` or `ZeroRttRejected` event. On rejection, Zoomies automatically resends streams as 1-RTT data.

## Streams

QUIC multiplexes data over streams within a single connection. Each stream is independent — no head-of-line blocking.

Stream IDs follow RFC 9000 §2.1. Client-initiated bidirectional streams use IDs 0, 4, 8, 12, … Server-initiated use 1, 5, 9, 13, …

```python
# Open a client-initiated bidirectional stream
conn.send_stream_data(0, b"hello")

# Receive stream data via events
case StreamDataReceived(stream_id=sid, data=data, end_stream=fin):
    ...
```

## Loss recovery

Zoomies implements RFC 9002:

- **RTT estimation** — EWMA smoothing of round-trip samples
- **Packet-number loss detection** — Mark lost after threshold
- **Time-based loss detection** — Timer-driven retransmission
- **PTO probing** — Probe Timeout with exponential backoff
- **NewReno congestion control** — cwnd gating in the send path

The recovery layer is integrated into `QuicConnection` — no extra setup needed.

## Close

Connections close via `CONNECTION_CLOSE` frame or idle timeout.

```python
case ConnectionClosed():
    # Clean up resources
    ...
```
