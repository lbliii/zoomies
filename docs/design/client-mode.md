# Client Mode Design

**Status**: Complete

Design document for adding QUIC client-side connection support to Zoomies.

## Overview

`QuicConnection` currently implements server-only QUIC. This document designs the client-side handshake, TLS flow, and API surface needed for `QuicConnection(config, is_client=True)`.

## Design Decisions

### D1: Two TLS classes, shared helpers

**Decision**: Add `QuicClientTlsContext` alongside existing `QuicTlsContext` (server). Do not merge them.

**Why**: The constructors differ (`cert+key` vs `ca_certs`), the state machines differ (server has 4 states, client has 7), and the receive logic branches completely. Shared code already lives in module-level functions (`_parse_client_hello`, `_build_server_hello`, `_hkdf_expand_label`, etc.). Adding client parsers/builders at module level keeps each class focused.

**Shared (module functions)**:
- Key schedule: `_hkdf_expand_label`, `_hkdf_extract`
- Block I/O: `_pull_block`, `_push_block`
- Message builders: `_build_finished`
- Constants: cipher suites, TLS versions, extension types

**New module functions for client**:
- `_build_client_hello(random, session_id, key_share, server_name)` — build ClientHello bytes
- `_parse_server_hello(data)` — extract random, session_id, key_share from ServerHello
- `_parse_encrypted_extensions(data)` — parse EE (may contain QUIC transport params)
- `_parse_certificate(data)` — extract certificate chain (list of DER bytes)
- `_parse_certificate_verify(data)` — extract algorithm + signature

### D2: Client TLS state machine

```
START
  │ build_client_hello()
  ▼
WAIT_SERVER_HELLO
  │ receive(ServerHello)  →  derive handshake_secret, return it
  ▼
WAIT_ENCRYPTED_EXTENSIONS
  │ receive(EncryptedExtensions)  →  store transport params
  ▼
WAIT_CERTIFICATE
  │ receive(Certificate)  →  store cert chain
  ▼
WAIT_CERTIFICATE_VERIFY
  │ receive(CertificateVerify)  →  verify signature against transcript
  ▼
WAIT_FINISHED
  │ receive(Finished)  →  verify MAC, build client Finished, derive traffic_secret
  ▼
HANDSHAKE_COMPLETE
```

The `receive()` method processes messages incrementally (multiple may arrive in one call). It returns a `TlsHandshakeResult` with:
- `state`: current state
- `data_to_send`: client Finished bytes (only after processing server Finished)
- `handshake_secret`: set after ServerHello
- `traffic_secret`: set after server Finished

This matches the server's `receive()` return type exactly — `QuicConnection` doesn't need to branch on result shape.

### D3: Key schedule (client perspective)

The key schedule is identical to the server's. The difference is which secrets are used for send vs receive:

```
early_secret     = HKDF-Extract(0, 0)
derived          = Expand-Label(early_secret, "derived", "", 32)
handshake_secret = HKDF-Extract(derived, shared_key)

  Client handshake keys:
    c_hs_traffic = Expand-Label(handshake_secret, "c hs traffic", CH..SH, 32)  → client SEND
    s_hs_traffic = Expand-Label(handshake_secret, "s hs traffic", CH..SH, 32)  → client RECV

derived2       = Expand-Label(handshake_secret, "derived", CH..SF, 32)
master_secret  = HKDF-Extract(derived2, 0)

  Client application keys:
    c_ap_traffic = Expand-Label(master_secret, "c ap traffic", CH..SF, 32)  → client SEND
    s_ap_traffic = Expand-Label(master_secret, "s ap traffic", CH..SF, 32)  → client RECV
```

`CryptoPair.setup_*` already handles the send/recv swap via `is_client`. No changes needed to `quic_crypto.py`.

### D4: Certificate verification

**Client `QuicConfiguration` additions**:
```python
@dataclass(frozen=True, slots=True)
class QuicConfiguration:
    is_client: bool = False
    certificate: bytes = b""      # required for server, ignored by client
    private_key: bytes = b""      # required for server, ignored by client
    ca_certs: bytes | None = None  # PEM CA bundle for client cert verification
    verify_mode: bool = True       # set False to skip verification (testing)
    server_name: str | None = None # SNI for client handshake
    max_data: int = 0
    max_stream_data: int = 0
    idle_timeout: float = 30.0
```

**Verification logic** (in `QuicClientTlsContext`):
- Load CA certs from `ca_certs` PEM bytes
- After receiving Certificate message, build chain and verify against CA store
- Use `cryptography.x509.verification` (available since cryptography 42.0)
- If `verify_mode=False`, skip verification entirely (for loopback tests)

### D5: QuicConnection changes

**`__init__`**: Check `config.is_client`. If client, skip TLS context creation (defer to `connect()`).

**New method `connect()`**:
```python
def connect(self) -> None:
    """Generate Initial packet with ClientHello. Call once, then send_datagrams()."""
    self._our_cid = os.urandom(8)
    self._our_cids = {self._our_cid}
    self._peer_cid = os.urandom(8)  # destination CID for Initial
    self._initial_crypto = CryptoPair()
    self._initial_crypto.setup_initial(cid=self._peer_cid, is_client=True)
    self._tls_ctx = QuicClientTlsContext(
        ca_certs=self._config.ca_certs,
        verify_mode=self._config.verify_mode,
    )
    client_hello = self._tls_ctx.build_client_hello(
        server_name=self._config.server_name,
    )
    self._queue_initial_crypto(client_hello)
    self._state = ConnectionState.INITIAL
```

Note: For Initial keys, the client uses the **destination CID** (the server's CID) as the key derivation input, per RFC 9001 §5.2. The server uses its own CID (which is the destination CID it received). Both derive the same keys.

**`_handle_initial` (client path)**:
- Client receives server's Initial packet
- Decrypt with Initial keys
- Parse CRYPTO frames → feed to `QuicClientTlsContext`
- If TLS returns `handshake_secret` → set up Handshake keys

**`_handle_handshake` (client path)**:
- Client receives server's Handshake packet(s)
- Decrypt with Handshake keys
- Parse CRYPTO frames → feed to TLS
- If TLS returns `data_to_send` (client Finished) → queue Handshake packet
- If TLS returns `traffic_secret` → set up 1-RTT keys
- Don't emit `HandshakeComplete` yet (wait for HANDSHAKE_DONE)

**HANDSHAKE_DONE handling**:
- Client: on receiving HANDSHAKE_DONE frame → emit `HandshakeComplete`
- Server: unchanged (sends HANDSHAKE_DONE after handshake)

### D6: Anti-amplification (client)

Per RFC 9000 §8.1: The client's address is considered validated by the server after completing the handshake. The client itself is never subject to anti-amplification limits (only the server is, before address validation). Set `_address_validated = True` in client `__init__`.

### D7: Stream ID allocation

RFC 9000 §2.1:
- Client-initiated bidirectional: 0, 4, 8, 12, ...
- Client-initiated unidirectional: 2, 6, 10, 14, ...
- Server-initiated bidirectional: 1, 5, 9, 13, ...
- Server-initiated unidirectional: 3, 7, 11, 15, ...

The existing `StreamId` type and `_get_or_create_stream` already handle this — stream IDs are caller-provided. No changes needed. H3 will use the correct IDs for client-initiated requests.

## API Surface (after implementation)

### Client usage
```python
from zoomies import QuicConnection, QuicConfiguration, H3Connection

config = QuicConfiguration(
    is_client=True,
    ca_certs=open("ca.pem", "rb").read(),
    server_name="example.com",
)
conn = QuicConnection(config)
conn.connect()

# Send Initial packet
for dg in conn.send_datagrams():
    sock.sendto(dg, server_addr)

# Receive server response, complete handshake
data, addr = sock.recvfrom(65535)
events = conn.datagram_received(data, addr)
# ... may need multiple recv rounds for full handshake

# After HandshakeComplete event:
h3 = H3Connection(sender=conn)
h3.send_headers(stream_id=0, headers=[
    (b":method", b"GET"),
    (b":path", b"/"),
    (b":scheme", b"https"),
    (b":authority", b"example.com"),
])
```

### Server usage (unchanged)
```python
config = QuicConfiguration(
    certificate=cert_pem,
    private_key=key_pem,
)
conn = QuicConnection(config)
# ... same as before
```

## Files Changed

| File | Change |
|------|--------|
| `src/zoomies/core/configuration.py` | Add `is_client`, `ca_certs`, `verify_mode`, `server_name`; make `certificate`/`private_key` optional |
| `src/zoomies/crypto/tls.py` | Add `QuicClientTlsContext`, client parsers/builders |
| `src/zoomies/core/connection.py` | Add `connect()`, client paths in `_handle_initial`/`_handle_handshake`, HANDSHAKE_DONE → HandshakeComplete for client |
| `tests/test_tls_client.py` | Unit tests for `QuicClientTlsContext` |
| `tests/test_client_server.py` | Loopback integration: client + server QuicConnection |

No changes to: `quic_crypto.py`, `events.py`, `h3/connection.py`, `packet/builder.py`, `packet/header.py`.

## Open Questions

1. **QUIC transport parameters in ClientHello**: The server currently doesn't include transport params in EncryptedExtensions. Should Sprint 1 add this, or defer? **Recommendation**: Defer — the loopback tests will work without transport param negotiation. Add in a follow-up.

2. **Session resumption / PSK**: Required for 0-RTT. Not needed for basic client mode. **Recommendation**: Defer to 0-RTT sprint.

3. **Multiple cipher suites**: Currently only AES-128-GCM. Sufficient for interop with the server. **Recommendation**: Defer broader cipher suite support.
