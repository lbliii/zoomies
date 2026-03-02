---
title: Zoomies
description: Free-threading-native QUIC and HTTP/3 for Python 3.14t — sans-I/O, typed
template: home.html
weight: 100
type: page
draft: false
lang: en
keywords: [zoomies, quic, http3, python, free-threading, nogil, sans-io]
category: home

blob_background: true

cta_buttons:
  - text: Releases
    url: /releases/
    style: primary
  - text: GitHub
    url: https://github.com/lbliii/zoomies
    style: secondary

show_recent_posts: false
---

## QUIC & HTTP/3, Sans-I/O

**Free-threading native. Typed. Pure Python.**

Zoomies is a sans-I/O protocol library for QUIC (RFC 9000) and HTTP/3 (RFC 9114). Native to the b-stack, it has no b-stack dependencies and works anywhere — pure Python, cryptography only, free-threaded Python 3.14t.

```python
from zoomies.core import QuicConnection, QuicConfiguration
from zoomies.events import HandshakeComplete

config = QuicConfiguration(certificate=cert, private_key=key)
conn = QuicConnection(config)

events = conn.datagram_received(datagram, addr)
for event in events:
    if isinstance(event, HandshakeComplete):
        ...
```

---

## What's good about it

:::{cards}
:columns: 2
:gap: medium

:::{card} Sans-I/O
:icon: cpu
Protocol layer consumes bytes, produces bytes. No socket access. Caller owns I/O.
:::{/card}

:::{card} Types as Contracts
:icon: check-circle
Frozen dataclasses for events, Protocols for handlers. Full IDE support.
:::{/card}

:::{card} Free-Threading Native
:icon: zap
No C extensions with limited API. Uses cryptography (3.14t-compatible).
:::{/card}

:::{card} Composition
:icon: package
Packet → Crypto → Stream → Connection → HTTP/3. Each layer testable in isolation.
:::{/card}

:::{/cards}

---

## Installation

```bash
pip install zoomies
```

Requires Python 3.14+.
