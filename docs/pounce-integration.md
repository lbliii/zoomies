# Pounce Integration Guide

Zoomies is framework-agnostic. This doc describes how Pounce integrates with Zoomies and wires it into its ASGI H3 bridge.

## API Surface

| Zoomies | Pounce Expectation |
|---------|--------------------|
| `QuicConnection.datagram_received(data, addr)` | Feed UDP datagrams in |
| `QuicConnection.send_datagrams()` | `transmit()` — flush QUIC packets |
| `H3Connection(quic_conn)` | `H3Connection` with sender |
| `H3Connection.handle_event(QuicEvent)` | Forward `StreamDataReceived` |
| `H3Connection.send_headers(stream_id, headers, end_stream)` | Response headers |
| `H3Connection.send_data(stream_id, data, end_stream)` | Response body |
| `H3HeadersReceived.headers` | `list[tuple[bytes, bytes]]` (ASGI) |

## Integration Pattern

```python
from zoomies import QuicConnection, QuicConfiguration, H3Connection
from zoomies.events import HandshakeComplete, H3HeadersReceived

config = QuicConfiguration(certificate=cert, private_key=key)
quic = QuicConnection(config)
h3 = H3Connection(sender=quic)

# UDP receive loop (Pounce owns the socket)
def on_datagram(data: bytes, addr: tuple[str, int]) -> None:
    events = quic.datagram_received(data, addr)
    for event in events:
        if isinstance(event, HandshakeComplete):
            # Create H3Connection on HandshakeComplete (Zoomies)
            # aioquic uses ProtocolNegotiated; Zoomies defers TLS/ALPN
            pass
        for h3_event in h3.handle_event(event):
            if isinstance(h3_event, H3HeadersReceived):
                scope = build_h3_scope(h3_event.headers, ...)
                receive = create_h3_receive(body_queue)
                send = create_h3_send(h3, h3_event.stream_id, transmit, ...)
                asgi_app(scope, receive, send)
    # transmit = flush QUIC packets
    for dg in quic.send_datagrams():
        sock.sendto(dg, addr)
```

## Key Differences from aioquic

1. **ProtocolNegotiated**: Zoomies does not yet emit `ProtocolNegotiated` (no TLS/ALPN). Pounce creates `H3Connection` on `HandshakeComplete` for Zoomies.
2. **Headers format**: `H3HeadersReceived.headers` is `list[tuple[bytes, bytes]]` for ASGI compatibility.
3. **transmit()**: Pounce implements `transmit()` as `for dg in quic.send_datagrams(): sock.sendto(dg, addr)`.

## Example

See `examples/h3_server_loop.py` for a minimal sans-I/O loop demonstrating the exact flow Pounce will implement.
