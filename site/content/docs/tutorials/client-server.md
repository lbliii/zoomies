---
title: HTTP/3 Client & Server
description: Run a full HTTP/3 request and response over QUIC using Zoomies' sans-I/O architecture.
weight: 20
---

## What you'll build

A loopback HTTP/3 client and server in a single script. The client sends a GET request, the server responds with a body, and both sides use `H3Connection` for HTTP/3 framing on top of `QuicConnection`.

## Prerequisites

- Python 3.14+
- Zoomies installed (`pip install bengal-zoomies`)
- A TLS certificate and key (self-signed is fine for testing)

## Generate test certificates

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost"
```

## The code

```python
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import H3DataReceived, H3HeadersReceived
from zoomies.h3 import H3Connection

ADDR = ("127.0.0.1", 4433)

# Load certs
with open("cert.pem", "rb") as f:
    cert = f.read()
with open("key.pem", "rb") as f:
    key = f.read()


def transfer(sender: QuicConnection, receiver: QuicConnection) -> list:
    """Move datagrams from sender to receiver, return events."""
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, ADDR))
    return events


def h3_events(quic_events: list, h3: H3Connection) -> list:
    """Feed QUIC events into H3, return H3 events."""
    out = []
    for evt in quic_events:
        out.extend(h3.handle_event(evt))
    return out


# --- Create connections ---

server_quic = QuicConnection(QuicConfiguration(certificate=cert, private_key=key))
client_quic = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))

h3_client = H3Connection(sender=client_quic)
h3_server = H3Connection(sender=server_quic)

# --- QUIC handshake ---

client_quic.connect()
transfer(client_quic, server_quic)
transfer(server_quic, client_quic)
transfer(client_quic, server_quic)
transfer(server_quic, client_quic)
print("Handshake complete")

# --- Client sends GET /hello ---

h3_client.send_headers(
    stream_id=0,
    headers=[
        (b":method", b"GET"),
        (b":path", b"/hello"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
    ],
    end_stream=True,
)

# --- Server receives and responds ---

server_events = h3_events(transfer(client_quic, server_quic), h3_server)
for evt in server_events:
    if isinstance(evt, H3HeadersReceived):
        headers = dict(evt.headers)
        print(f"Server received: {headers[b':method'].decode()} {headers[b':path'].decode()}")

h3_server.send_headers(
    stream_id=0,
    headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
    end_stream=False,
)
h3_server.send_data(stream_id=0, data=b"Hello from Zoomies!", end_stream=True)

# --- Client receives response ---

client_events = h3_events(transfer(server_quic, client_quic), h3_client)
for evt in client_events:
    if isinstance(evt, H3HeadersReceived):
        status = dict(evt.headers)[b":status"].decode()
        print(f"Client received: HTTP/3 {status}")
    elif isinstance(evt, H3DataReceived):
        print(f"Body: {evt.data.decode()}")

# --- Close ---

client_quic.close(error_code=0, reason="done")
transfer(client_quic, server_quic)
print("Done.")
```

## What's happening

1. **Two QuicConnections** — One client, one server. They exchange datagrams in memory via the `transfer()` helper (in production you'd use real UDP sockets).
2. **connect()** — The client initiates the TLS 1.3 handshake. Four `transfer()` calls complete the round-trips.
3. **H3Connection** — Sits on top of QUIC, handling HTTP/3 framing, QPACK header encoding, and stream management.
4. **send_headers / send_data** — HTTP/3 request and response, each carried on QUIC stream 0.

## Next steps

- [0-RTT early data](../../concepts/connection-lifecycle/#0-rtt-early-data) — send data before the handshake completes
- [QPACK dynamic table](../../concepts/http3/#dynamic-table) — how repeated headers get compressed
- [Events reference](../../reference/events/) — all event types your application can handle
