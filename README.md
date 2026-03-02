# ⚡ Zoomies

[![PyPI version](https://img.shields.io/pypi/v/zoomies.svg)](https://pypi.org/project/zoomies/)
[![Build Status](https://github.com/lbliii/zoomies/actions/workflows/tests.yml/badge.svg)](https://github.com/lbliii/zoomies/actions/workflows/tests.yml)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://pypi.org/project/zoomies/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status: Pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)](https://pypi.org/project/zoomies/)

**Free-threading-native QUIC and HTTP/3 for Python 3.14t — sans-I/O, typed**

```python
from zoomies.core import QuicConnection, QuicConfiguration
from zoomies.events import HandshakeComplete

config = QuicConfiguration(is_client=False)
conn = QuicConnection(config)

# Sans-I/O: feed datagrams in, get events out
for event in conn.receive_datagram(datagram, addr):
    if isinstance(event, HandshakeComplete):
        ...
for datagram, addr in conn.datagrams_to_send():
    sock.sendto(datagram, addr)
```

---

## What is Zoomies?

Zoomies is a sans-I/O protocol library for QUIC (RFC 9000) and HTTP/3 (RFC 9114). It's designed for Pounce and Chirp, built for free-threaded Python 3.14t.

**What's good about it:**

- **Sans-I/O** — Protocol layer consumes bytes, produces bytes. No socket access. Caller owns I/O.
- **Types as contracts** — Frozen dataclasses for events, Protocols for handlers.
- **Free-threading native** — No C extensions with limited API. Uses cryptography (3.14t-compatible).
- **Composition** — Packet → Crypto → Stream → Connection → HTTP/3. Each layer testable in isolation.

---

## What it does

| API | Description |
|-----|-------------|
| `QuicConnection.receive_datagram()` | Feed UDP datagram in, get protocol events |
| `QuicConnection.datagrams_to_send()` | Get outbound datagrams to transmit |
| `H3Connection` | HTTP/3 connection state machine (QPACK, streams) |
| `encode_headers` / `decode_headers` | QPACK header compression |
| `pull_quic_header()` | Parse QUIC packet headers (Initial, Handshake, etc.) |

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
from zoomies.core import QuicConnection, QuicConfiguration
from zoomies.events import HandshakeComplete

config = QuicConfiguration(is_client=False)
# config.load_cert_chain("cert.pem", "key.pem")
conn = QuicConnection(config)

for event in conn.receive_datagram(datagram, addr):
    if isinstance(event, HandshakeComplete):
        print("Handshake done!")
for dg, a in conn.datagrams_to_send():
    sock.sendto(dg, a)
```

**Run the examples** (from repo root):

```bash
uv run python -m examples.qpack_roundtrip
uv run python -m examples.parse_initial_packet
uv run python -m examples.sans_io_connection
```

---

## Examples

| Example | Description |
|---------|-------------|
| `examples/qpack_roundtrip.py` | QPACK header encode/decode |
| `examples/parse_initial_packet.py` | Parse QUIC Initial packet header |
| `examples/sans_io_connection.py` | Sans-I/O `QuicConnection` demo (uses test fixtures) |

---

## Usage

<details>
<summary><strong>Events</strong> — Frozen dataclasses for protocol state changes</summary>

```python
from zoomies.events import (
    DatagramReceived,
    HandshakeComplete,
    StreamDataReceived,
    ConnectionClosed,
)

for event in conn.receive_datagram(datagram, addr):
    match event:
        case HandshakeComplete():
            ...
        case StreamDataReceived(stream_id=id, data=data):
            ...
        case ConnectionClosed():
            ...
```

</details>

<details>
<summary><strong>HTTP/3</strong> — H3Connection for request/response</summary>

```python
from zoomies.h3 import H3Connection, H3HeadersReceived, H3DataReceived

h3 = H3Connection(is_client=False)
# Feed H3 frames from QUIC streams into h3.receive_*()
# Handle H3HeadersReceived, H3DataReceived events
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

## The Bengal Ecosystem

A structured reactive stack — every layer written in pure Python for 3.14t free-threading.

| | | | |
|--:|---|---|---|
| **ᓚᘏᗢ** | [Bengal](https://github.com/lbliii/bengal) | Static site generator | [Docs](https://lbliii.github.io/bengal/) |
| **∿∿** | [Purr](https://github.com/lbliii/purr) | Content runtime | — |
| **⌁⌁** | [Chirp](https://github.com/lbliii/chirp) | Web framework | [Docs](https://lbliii.github.io/chirp/) |
| **=^..^=** | [Pounce](https://github.com/lbliii/pounce) | ASGI server | [Docs](https://lbliii.github.io/pounce/) |
| **)彡** | [Kida](https://github.com/lbliii/kida) | Template engine | [Docs](https://lbliii.github.io/kida/) |
| **ฅᨐฅ** | [Patitas](https://github.com/lbliii/patitas) | Markdown parser | [Docs](https://lbliii.github.io/patitas/) |
| **⌾⌾⌾** | [Rosettes](https://github.com/lbliii/rosettes) | Syntax highlighter | [Docs](https://lbliii.github.io/rosettes/) |
| **⚡** | **Zoomies** | QUIC/HTTP/3 ← You are here | — |

Python-native. Free-threading ready. No npm required.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
