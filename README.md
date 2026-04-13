# ⟢⟣ Zoomies

[![PyPI version](https://img.shields.io/pypi/v/zoomies.svg)](https://pypi.org/project/zoomies/)
[![Build Status](https://github.com/lbliii/zoomies/actions/workflows/tests.yml/badge.svg)](https://github.com/lbliii/zoomies/actions/workflows/tests.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://pypi.org/project/zoomies/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)](https://pypi.org/project/zoomies/)

**Free-threading-native QUIC and HTTP/3 for Python 3.14t — sans-I/O, typed**

```python
import time
from zoomies.core import QuicConnection, QuicConfiguration
from zoomies.events import HandshakeComplete

config = QuicConfiguration(certificate=cert, private_key=key)
conn = QuicConnection(config)

# Sans-I/O: feed datagrams in, get events out
now = time.monotonic()
events = conn.datagram_received(datagram, addr, now=now)
for event in events:
    if isinstance(event, HandshakeComplete):
        ...
for dg in conn.send_datagrams(now=now):
    sock.sendto(dg, addr)
```

---

## What is Zoomies?

Zoomies is a sans-I/O protocol library for QUIC (RFC 9000) and HTTP/3 (RFC 9114). Native to the b-stack (Pounce, Chirp), it has no b-stack dependencies and works anywhere — pure Python, cryptography only, free-threaded Python 3.14t. Alpha: full TLS 1.3 handshake, 1-RTT packets, loss recovery (RFC 9002), and congestion control.

**What's good about it:**

- **Sans-I/O** — Protocol layer consumes bytes, produces bytes. No socket access. Caller owns I/O.
- **Types as contracts** — Frozen dataclasses for events, Protocols for handlers.
- **Free-threading native** — No C extensions with limited API. Uses cryptography (3.14t-compatible).
- **Composition** — Packet → Crypto → Stream → Connection → Recovery → HTTP/3. Each layer testable in isolation.
- **Loss recovery** — RFC 9002 loss detection, RTT estimation, NewReno congestion control. Built into the connection layer.

---

## What it does

| API | Description |
|-----|-------------|
| `QuicConnection.datagram_received(data, addr, now=)` | Feed UDP datagram in, get protocol events |
| `QuicConnection.send_datagrams(now=)` | Get outbound datagrams to transmit |
| `QuicConnection.send_stream_data(stream_id, data, end_stream)` | Queue application data on a QUIC stream |
| `QuicConnection.get_timer()` | Next deadline for `handle_timer()` (see Timer Integration) |
| `QuicConnection.handle_timer(now)` | Process timer expiry (idle timeout, PTO retransmission) |
| `QuicConnection.connect()` | Client: generate Initial packet with ClientHello |
| `QuicConnection.close()` | Send CONNECTION_CLOSE and shut down |
| `H3Connection.handle_event(event)` | Process QUIC events into HTTP/3 events |
| `encode_headers` / `decode_headers` | QPACK header compression |
| `pull_quic_header()` | Parse QUIC packet headers (Initial, Handshake, etc.) |
| `zoomies.recovery` | Loss detection, RTT estimation, congestion control (RFC 9002) |

**Key events:** `HandshakeComplete`, `StreamDataReceived`, `ConnectionClosed`, `NewSessionTicket`, `ZeroRttAccepted`, `ZeroRttRejected`, `PacketDropped`, `DecryptionFailed`

---

## Installation

```bash
pip install zoomies
```

Requires Python 3.14+

---

## Quick Start

### QPACK encode/decode

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

### Parse QUIC Initial packet

```python
from zoomies.encoding import Buffer
from zoomies.packet import pull_quic_header

buf = Buffer(data=raw_bytes)
header = pull_quic_header(buf, host_cid_length=None)
print(f"Version: {header.version:#x}, CID: {header.destination_cid}")
```

### Sans-I/O connection (server)

```python
import time
from zoomies.core import QuicConnection, QuicConfiguration
from zoomies.events import HandshakeComplete

with open("cert.pem", "rb") as f:
    cert = f.read()
with open("key.pem", "rb") as f:
    key = f.read()
config = QuicConfiguration(certificate=cert, private_key=key)
conn = QuicConnection(config)

now = time.monotonic()
events = conn.datagram_received(datagram, addr, now=now)
for event in events:
    if isinstance(event, HandshakeComplete):
        print("Handshake done!")
for dg in conn.send_datagrams(now=now):
    sock.sendto(dg, addr)
```

### Sans-I/O connection (client)

```python
import time
from zoomies.core import QuicConnection, QuicConfiguration

config = QuicConfiguration(is_client=True, verify_mode=False)  # test only — use ca_certs in production
conn = QuicConnection(config)
conn.connect()

now = time.monotonic()
for dg in conn.send_datagrams(now=now):
    sock.sendto(dg, server_addr)
```

### Timer integration (required for production use)

Zoomies is sans-I/O: the library never sleeps. **You must drive the timer** by polling
`get_timer()` and calling `handle_timer()` when the deadline passes. Without this,
idle timeouts and PTO retransmissions won't fire.

```python
import time

while True:
    now = time.monotonic()
    # 1. Process incoming datagrams
    for dg in receive_from_socket():
        events = conn.datagram_received(dg, addr, now=now)
        handle_events(events)

    # 2. Send outbound datagrams
    for dg in conn.send_datagrams(now=now):
        sock.sendto(dg, addr)

    # 3. Drive the timer — this is what makes idle_timeout and PTO work
    deadline = conn.get_timer()
    if deadline is not None and now >= deadline:
        events = conn.handle_timer(now)
        handle_events(events)
```

See `examples/realistic_server.py` for a complete `select()`-based implementation.

### 0-RTT early data (TLS resumption)

After a first connection, capture the session ticket and reuse it to send data before
the handshake completes on reconnection:

```python
from zoomies.events import NewSessionTicket, ZeroRttAccepted, ZeroRttRejected

# 1. First connection: capture the session ticket
for event in events:
    if isinstance(event, NewSessionTicket):
        stored_ticket = event.ticket  # save externally (file, DB, etc.)

# 2. Reconnect with the ticket
config = QuicConfiguration(is_client=True, session_ticket=stored_ticket, ...)
conn = QuicConnection(config)
conn.connect()

# 3. Queue data immediately (sent as 0-RTT before handshake completes)
conn.send_stream_data(stream_id=0, data=b"early request", end_stream=True)

# 4. Check if the server accepted 0-RTT
for event in events:
    if isinstance(event, ZeroRttAccepted):
        pass  # early data was accepted
    elif isinstance(event, ZeroRttRejected):
        pass  # resend data — it will go as 1-RTT after handshake
```

See `examples/zero_rtt_resumption.py` for the full end-to-end flow.

**Run the examples** (from repo root):

```bash
uv run python -m examples.qpack_roundtrip
uv run python -m examples.parse_initial_packet
uv run python -m examples.sans_io_connection
uv run python -m examples.client_server
```

---

## Examples

| Example | Description |
|---------|-------------|
| `examples/qpack_roundtrip.py` | QPACK header encode/decode |
| `examples/parse_initial_packet.py` | Parse QUIC Initial packet header |
| `examples/sans_io_connection.py` | Sans-I/O `QuicConnection` demo (uses test fixtures) |
| `examples/stream_echo.py` | Stream reassembly, RTT estimation, congestion control, loss detection, PTO timer loop |
| `examples/client_server.py` | HTTP/3 GET request/response over loopback (client + server in one process) |

---

## Usage

<details>
<summary><strong>Events</strong> — Frozen dataclasses for protocol state changes</summary>

```python
from zoomies.events import (
    HandshakeComplete,
    StreamDataReceived,
    StreamReset,
    ConnectionClosed,
)

for event in conn.datagram_received(datagram, addr):
    match event:
        case HandshakeComplete():
            ...
        case StreamDataReceived(stream_id=sid, data=data):
            ...
        case StreamReset(stream_id=sid, error_code=code):
            ...
        case ConnectionClosed():
            ...
```

</details>

<details>
<summary><strong>HTTP/3</strong> — H3Connection for request/response</summary>

```python
from zoomies.h3 import H3Connection
from zoomies.events import H3HeadersReceived, H3DataReceived

# Wrap a QuicConnection to add HTTP/3 framing
h3 = H3Connection(sender=quic_conn)

# Client: send request
h3.send_headers(stream_id=0, headers=[
    (b":method", b"GET"), (b":path", b"/"),
    (b":scheme", b"https"), (b":authority", b"localhost"),
], end_stream=True)

# Server: process QUIC events through H3
for quic_event in events:
    for h3_event in h3.handle_event(quic_event):
        match h3_event:
            case H3HeadersReceived(headers=hdrs):
                ...
            case H3DataReceived(data=body):
                ...
```

</details>

<details>
<summary><strong>Free-threading</strong> — Python 3.14t</summary>

Zoomies uses frozen dataclasses, no shared mutable state, and `cryptography` (3.14t-compatible). Safe to run multiple `QuicConnection` instances from different threads.

</details>

---

## Development

```bash
git clone https://github.com/lbliii/zoomies.git
cd zoomies
uv sync --group dev
pytest
```

**Lint and types:**

```bash
ruff check src tests
ty check
```

---

## Related: The Bengal Ecosystem

Zoomies is developed as part of the b-stack but is standalone. No imports from Bengal, Chirp, or Pounce. A structured reactive stack — every layer written in pure Python for 3.14t free-threading.

| | | | |
|--:|---|---|---|
| **ᓚᘏᗢ** | [Bengal](https://github.com/lbliii/bengal) | Static site generator | [Docs](https://lbliii.github.io/bengal/) |
| **∿∿** | [Purr](https://github.com/lbliii/purr) | Content runtime | — |
| **⌁⌁** | [Chirp](https://github.com/lbliii/chirp) | Web framework | [Docs](https://lbliii.github.io/chirp/) |
| **=^..^=** | [Pounce](https://github.com/lbliii/pounce) | ASGI server | [Docs](https://lbliii.github.io/pounce/) |
| **)彡** | [Kida](https://github.com/lbliii/kida) | Template engine | [Docs](https://lbliii.github.io/kida/) |
| **ฅᨐฅ** | [Patitas](https://github.com/lbliii/patitas) | Markdown parser | [Docs](https://lbliii.github.io/patitas/) |
| **⌾⌾⌾** | [Rosettes](https://github.com/lbliii/rosettes) | Syntax highlighter | [Docs](https://lbliii.github.io/rosettes/) |
| **⟢⟣** | **Zoomies** | QUIC/HTTP/3 ← You are here | — |

Python-native. Free-threading ready. No npm required.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
