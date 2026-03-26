---
title: Configuration
description: QuicConfiguration options for connections.
weight: 20
---

## QuicConfiguration

`QuicConfiguration` holds the settings for a QUIC connection.

```python
from zoomies.core import QuicConfiguration

config = QuicConfiguration(
    certificate=cert_bytes,
    private_key=key_bytes,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `certificate` | `bytes \| None` | `None` | PEM-encoded certificate (required for server) |
| `private_key` | `bytes \| None` | `None` | PEM-encoded private key (required for server) |
| `is_client` | `bool` | `False` | Client or server role |
| `alpn_protocols` | `list[str]` | `["h3"]` | ALPN protocol negotiation list |
| `max_stream_data` | `int` | `1048576` | Per-stream flow control limit (bytes) |
| `idle_timeout` | `float` | `30.0` | Connection idle timeout (seconds) |

## Server configuration

```python
with open("cert.pem", "rb") as f:
    cert = f.read()
with open("key.pem", "rb") as f:
    key = f.read()

config = QuicConfiguration(certificate=cert, private_key=key)
```

## Client configuration

```python
config = QuicConfiguration(is_client=True)
```
