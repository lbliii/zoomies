# Zoomies Roadmap

## Previous: Alpha (0.2.x)

- TLS 1.3 handshake (cryptography) — Handshake + 1-RTT keys
- Handshake packet handling — CRYPTO frames, TLS in Handshake packets
- 1-RTT receive — Short header decrypt, stream delivery
- 1-RTT send — flush queued stream data to Short header packets
- H3Connection, QPACK (static table, O(1) lookup), stream parsing
- ACK generation — per-space packet number tracking
- Stream reassembly — ordered delivery, send offset tracking
- CONNECTION_CLOSE, STOP_SENDING, RESET_STREAM frames
- Loss detection — packet-number and time-based (RFC 9002)
- NewReno congestion control — cwnd gating (RFC 9002 §7)
- RTT estimation — EWMA smoothing (RFC 9002 §5.3)
- PTO probing with exponential backoff
- Anti-amplification enforcement (3x limit)
- Flow control enforcement, idle timeout
- Key update rotation (HKDF "quic ku")
- Sans-I/O timer pattern, sans-I/O API stable

**Target achieved:** End-to-end GET / with HTTP/3 response over real TLS, with loss recovery and congestion control.

## Current: Beta (0.3.x) — Interoperable

- ~~Client mode~~ **Done** — client-side QUIC + HTTP/3 with loopback tests
- ~~QPACK dynamic table~~ **Done** — RFC 9204 encoder/decoder
- ~~0-RTT early data~~ **Done** — PSK resumption with send/receive and anti-replay
- Retry packet generation
- Version negotiation
- Connection migration / CID retirement

**Target achieved:** Client and server mode with 0-RTT, QPACK dynamic table, and constant-time TLS verification.

## Production (0.4+) — Optional

1. Multipath QUIC
2. ECN support
3. Performance tuning and benchmarks against aioquic
