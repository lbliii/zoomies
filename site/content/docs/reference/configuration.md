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
| `is_client` | `bool` | `False` | Client or server role |
| `certificate` | `bytes` | `b""` | PEM-encoded certificate (required for server) |
| `private_key` | `bytes` | `b""` | PEM-encoded private key (required for server) |
| `ca_certs` | `bytes \| None` | `None` | PEM-encoded CA bundle for peer verification |
| `verify_mode` | `bool` | `True` | Verify the peer's certificate chain |
| `server_name` | `str \| None` | `None` | SNI hostname (client only) |
| `max_data` | `int` | `0` | Connection-level flow control limit (bytes) |
| `max_stream_data` | `int` | `0` | Per-stream flow control limit (bytes) |
| `idle_timeout` | `float` | `30.0` | Connection idle timeout (seconds) |
| `session_ticket` | `SessionTicket \| None` | `None` | Stored session ticket for 0-RTT resumption (client only) |
| `zero_rtt_policy` | `ZeroRttPolicy \| None` | `None` | Replay protection policy for 0-RTT data (server only) |
| `retry_token_handler` | `RetryTokenHandler \| None` | `None` | Token handler for stateless address validation (server only) |

### ZeroRttPolicy

A protocol class you implement to control whether the server accepts 0-RTT early data:

```python
class ZeroRttPolicy(Protocol):
    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        """Return True to accept 0-RTT data for this ticket."""
        ...
```

### SessionTicket

Issued by the server after a successful handshake. Store it on the client and pass it back via `session_ticket` on reconnection to enable 0-RTT.

```python
from zoomies.crypto.tls import SessionTicket
```

| Field | Type | Description |
|-------|------|-------------|
| `ticket` | `bytes` | Opaque ticket data |
| `resumption_secret` | `bytes` | PSK derived from the original handshake |
| `max_early_data` | `int` | Maximum 0-RTT data size (default `0xFFFFFFFF`) |
| `cipher_suite` | `int` | TLS cipher suite identifier |
| `timestamp` | `float` | When the ticket was issued (default `0.0`) |
| `lifetime` | `int` | Ticket validity in seconds (default `7200`) |
| `age_add` | `int` | Obfuscated ticket age addend (default `0`) |
| `nonce` | `bytes` | Ticket nonce (default `b""`) |

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
config = QuicConfiguration(
    is_client=True,
    server_name="example.com",
)
```
