# Zoomies Roadmap

## Current: Alpha (0.2.x)

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

## Beta (0.3.x) — Interoperable

1. Retry packet generation
2. Version negotiation
3. Connection migration / CID retirement
4. Client mode
5. QPACK dynamic table

## Production (0.4+) — Optional

1. 0-RTT data
2. Multipath QUIC
3. ECN support
4. Performance tuning and benchmarks against aioquic
