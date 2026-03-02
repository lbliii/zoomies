# Zoomies Roadmap

## Current: Alpha (0.2.x)

- TLS 1.3 handshake (cryptography) — Handshake + 1-RTT keys
- Handshake packet handling — CRYPTO frames, TLS in Handshake packets
- 1-RTT receive — Short header decrypt, stream delivery
- 1-RTT send — flush queued stream data to Short header packets
- H3Connection, QPACK, stream parsing
- Sans-I/O API stable

**Target achieved:** End-to-end GET / with HTTP/3 response over real TLS (use `curl --http3` or similar).

## Beta (0.3.x) — Interoperable

1. Retry packet generation
2. Version negotiation
3. ACK handling, basic RTT
4. Connection close (CONNECTION_CLOSE frame)

## Production (0.4+) — Optional

1. Recovery (congestion control, loss detection)
2. Connection migration / CID retirement
3. Client mode
4. QPACK dynamic table
