---
title: Connection Lifecycle
description: QUIC connection states — handshake, streams, loss recovery, and close.
weight: 20
---

## Overview

A QUIC connection progresses through well-defined states. Zoomies models each as events emitted from `QuicConnection`.

```
Initial → Handshake → 1-RTT (application data) → Close
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

## Streams

QUIC multiplexes data over streams within a single connection. Each stream is independent — no head-of-line blocking.

```python
# Open a stream and send data
stream_id = conn.get_next_stream_id()
conn.send_stream_data(stream_id, b"hello")

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
