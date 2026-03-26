---
title: Build an Echo Server
description: Wire Zoomies to a UDP socket and echo stream data back to the client.
weight: 10
---

## What you'll build

A minimal QUIC echo server that:

1. Accepts a connection
2. Receives stream data
3. Echoes it back on the same stream
4. Handles loss recovery timers

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

## The server

```python
import socket
from zoomies.core import QuicConnection, QuicConfiguration
from zoomies.events import HandshakeComplete, StreamDataReceived

# Load certs
with open("cert.pem", "rb") as f:
    cert = f.read()
with open("key.pem", "rb") as f:
    key = f.read()

config = QuicConfiguration(certificate=cert, private_key=key)
conn = QuicConnection(config)

# Bind UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 4433))
print("Listening on :4433")

while True:
    data, addr = sock.recvfrom(65535)
    events = conn.datagram_received(data, addr)

    for event in events:
        match event:
            case HandshakeComplete():
                print(f"Handshake complete with {addr}")
            case StreamDataReceived(stream_id=sid, data=payload):
                print(f"Stream {sid}: {payload!r}")
                conn.send_stream_data(sid, payload)  # echo

    for dg in conn.send_datagrams():
        sock.sendto(dg, addr)

    # Handle timers
    timeout = conn.get_timer()
    if timeout is not None:
        sock.settimeout(max(0, timeout - __import__("time").monotonic()))
```

## What's happening

1. **UDP socket** — You own the socket. Zoomies never touches it.
2. **datagram_received** — Raw UDP bytes go in, protocol events come out.
3. **send_datagrams** — Zoomies produces response bytes. You send them.
4. **Timers** — Loss recovery needs periodic wakeups. `get_timer()` tells you when.

## Next steps

- [HTTP/3 concepts](../../concepts/http3/) — add request/response handling
- [Connection lifecycle](../../concepts/connection-lifecycle/) — understand what happens under the hood
