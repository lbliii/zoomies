---
title: Quickstart
description: Parse a QUIC packet and run a sans-I/O connection in five minutes.
weight: 20
---

## Parse a QUIC header

```python
from zoomies.encoding import Buffer
from zoomies.packet import pull_quic_header

buf = Buffer(data=raw_bytes)
header = pull_quic_header(buf, host_cid_length=None)
print(f"Version: {header.version:#x}, CID: {header.destination_cid}")
```

## QPACK encode/decode

```python
from zoomies.h3 import Header, decode_headers, encode_headers

headers = [
    Header(name=":method", value="GET"),
    Header(name=":path", value="/api/users"),
    Header(name=":scheme", value="https"),
]
encoded = encode_headers(headers)
decoded = decode_headers(encoded)
```

## Sans-I/O connection

Zoomies never touches sockets. You feed datagrams in, get events and outbound datagrams out.

```python
from zoomies.core import QuicConnection, QuicConfiguration
from zoomies.events import HandshakeComplete

config = QuicConfiguration(certificate=cert, private_key=key)
conn = QuicConnection(config)

# Feed a received UDP datagram
events = conn.datagram_received(datagram, addr)
for event in events:
    if isinstance(event, HandshakeComplete):
        print("Handshake done!")

# Get datagrams to send
for dg in conn.send_datagrams():
    sock.sendto(dg, addr)
```

## Next steps

- [Concepts: Sans-I/O pattern](../concepts/sans-io/) — understand the design
- [Concepts: Connection lifecycle](../concepts/connection-lifecycle/) — handshake through close
- [Reference: Events](../reference/events/) — all event types
