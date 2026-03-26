---
title: HTTP/3
description: H3Connection, QPACK header compression, and request/response handling.
weight: 30
---

## Overview

HTTP/3 runs over QUIC instead of TCP. Zoomies provides `H3Connection` as a state machine that sits on top of `QuicConnection`.

```
QuicEvent → H3Connection.handle_event() → H3Event
```

## QPACK

QPACK is the header compression format for HTTP/3 (replacing HPACK from HTTP/2).

```python
from zoomies.h3 import Header, encode_headers, decode_headers

headers = [
    Header(name=":method", value="GET"),
    Header(name=":path", value="/"),
    Header(name=":scheme", value="https"),
]
encoded = encode_headers(headers)
decoded = decode_headers(encoded)
```

Zoomies uses the QPACK static table with O(1) dict lookup and a bytes-native encode path.

## H3Connection

```python
from zoomies.h3 import H3Connection, H3HeadersReceived, H3DataReceived

h3 = H3Connection(is_client=False)

# Feed QUIC events into H3
for h3_event in h3.handle_event(quic_event):
    match h3_event:
        case H3HeadersReceived(headers=hdrs, stream_id=sid):
            ...
        case H3DataReceived(data=data, stream_id=sid):
            ...
```

## Integration with Pounce

In the b-stack, Pounce (ASGI server) wraps Zoomies to serve HTTP/3:

```
UDP socket → Zoomies QuicConnection → H3Connection → Pounce ASGI scope → Your app
```

Zoomies has no dependency on Pounce. The integration is one-directional.
