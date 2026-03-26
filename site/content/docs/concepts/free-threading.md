---
title: Free-Threading
description: Running Zoomies with Python 3.14t — no GIL, true parallelism.
weight: 40
---

## What is free-threading?

Python 3.13+ introduced an experimental free-threaded build (`python3.14t`) that disables the Global Interpreter Lock (GIL). Multiple threads can execute Python bytecode simultaneously.

## Why Zoomies is free-threading native

Zoomies was built from scratch for 3.14t:

- **No C extensions with limited API** — Only depends on `cryptography`, which is 3.14t-compatible
- **Frozen dataclasses** — All events are immutable. No shared mutable state between threads
- **No global state** — Each `QuicConnection` is independent
- **Sans-I/O** — No internal threads, locks, or async. The caller controls concurrency

## Running with free-threading

```bash
# Install Python 3.14t
uv python install 3.14t

# Disable GIL
PYTHON_GIL=0 python3.14t your_server.py
```

## Thread-safe patterns

Each `QuicConnection` instance should be owned by one thread. Multiple connections can run in parallel across threads without synchronization.

```python
import threading
from zoomies.core import QuicConnection, QuicConfiguration

def handle_connection(config, datagram, addr):
    conn = QuicConnection(config)
    events = conn.datagram_received(datagram, addr)
    # ... handle events ...

# Each thread gets its own connection — no locks needed
for datagram, addr in incoming:
    t = threading.Thread(target=handle_connection, args=(config, datagram, addr))
    t.start()
```

## Verifying free-threading

```python
import sys
print(sys._is_gil_enabled())  # False on 3.14t with PYTHON_GIL=0
```
