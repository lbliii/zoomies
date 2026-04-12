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

### Dynamic table

As of 0.3.0, Zoomies supports the QPACK dynamic table (RFC 9204). Repeated headers are indexed into a size-bounded table, compressing them ~60% smaller on subsequent requests.

The dynamic table is negotiated automatically via HTTP/3 SETTINGS. Encoder and decoder instruction streams handle table synchronization between peers. No application-level configuration is needed — `H3Connection` manages capacity negotiation and eviction internally.

## H3Connection

`H3Connection` wraps a `QuicConnection` (passed as `sender`) so it can emit stream data directly.

```python
from zoomies.h3 import H3Connection, H3HeadersReceived, H3DataReceived

h3 = H3Connection(sender=quic_conn)

# QUIC events that carry stream data produce H3 events
match quic_event:
    case StreamDataReceived(stream_id=sid, data=data, end_stream=fin):
        for h3_event in h3.handle_event(quic_event):
            match h3_event:
                case H3HeadersReceived(headers=hdrs, stream_id=sid):
                    ...
                case H3DataReceived(data=body, stream_id=sid):
                    ...
```

Optional keyword arguments control QPACK dynamic table capacity:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sender` | `H3StreamSender \| None` | `None` | Underlying QUIC connection |
| `qpack_max_table_capacity` | `int` | `0` | Dynamic table size limit (bytes) |
| `qpack_blocked_streams` | `int` | `0` | Max streams blocked on decoder |

## Integration with Pounce

In the b-stack, Pounce (ASGI server) wraps Zoomies to serve HTTP/3:

```
UDP socket → Zoomies QuicConnection → H3Connection → Pounce ASGI scope → Your app
```

Zoomies has no dependency on Pounce. The integration is one-directional.
