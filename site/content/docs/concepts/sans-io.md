---
title: Sans-I/O Pattern
description: How Zoomies separates protocol logic from network I/O.
weight: 10
---

## What is sans-I/O?

Sans-I/O means the protocol library never touches sockets, files, or any I/O primitives. It consumes bytes and produces bytes. The caller owns I/O.

```
datagram in → QuicConnection.datagram_received() → [QuicEvent, ...]
                                                  → QuicConnection.send_datagrams() → [bytes, ...]
```

## Why?

- **Testable** — Feed bytes in, assert on events out. No mocks needed.
- **Portable** — Works with asyncio, threading, bare sockets, or any event loop.
- **Composable** — Pounce (ASGI server) wraps Zoomies with its own I/O layer. You can too.

## The contract

Every Zoomies API follows the same pattern:

1. **Input**: Call a method with raw bytes or protocol data
2. **Process**: Internal state machine advances
3. **Output**: Get events (what happened) and datagrams (what to send)

```python
# You own the socket
events = conn.datagram_received(datagram, addr)

# React to events
for event in events:
    match event:
        case HandshakeComplete():
            ...
        case StreamDataReceived(stream_id=sid, data=data):
            ...

# Send what the connection produced
for dg in conn.send_datagrams():
    sock.sendto(dg, addr)
```

## Timer callbacks

Loss recovery requires timers (PTO, idle timeout). Zoomies exposes a `get_timer()` method. You call it, schedule a wakeup, and call `handle_timer()` when it fires.

```python
timeout = conn.get_timer()
if timeout is not None:
    # schedule a wakeup at `timeout` (absolute time)
    ...

# When the timer fires:
events = conn.handle_timer()
for dg in conn.send_datagrams():
    sock.sendto(dg, addr)
```

## See also

- [sans-I/O manifesto](https://sans-io.readthedocs.io/) — the original proposal
- [Architecture](../about/architecture/) — how Zoomies layers compose
