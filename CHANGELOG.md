# Changelog

All notable changes to Zoomies will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-04-10

### Fixed

- Export `ZeroRttAccepted` and `ZeroRttRejected` events from top-level `zoomies` package
- Export `QpackEncoder` and `QpackDecoder` from `zoomies.h3` subpackage
- Bump `__version__` from `0.1.0` to match `pyproject.toml` (was never updated in 0.3.0)
- Correct event names in docs: `ZeroRttAccepted`/`ZeroRttRejected` (not `EarlyDataAccepted`/`EarlyDataRejected`)

## [0.3.0] - 2026-04-10

### Added

- **QPACK dynamic table** (`zoomies.h3`) — Full RFC 9204 encoder/decoder with dynamic table support
  - `DynamicTable` for header field indexing with size-bounded eviction
  - Encoder and decoder instruction streams (`qpack_instructions`)
  - Adversarial input protection and property-based testing
  - `H3Connection` settings negotiation for dynamic table capacity
- **QUIC client mode** — Full client-side QUIC and HTTP/3 support
  - Client-initiated handshake with TLS 1.3 ClientHello
  - Loopback client/server integration tests
  - HTTP/3 client request/response over QUIC
  - `client_server.py` example for end-to-end usage
- **0-RTT early data** — PSK resumption with early data send/receive
  - Pre-shared key (PSK) storage and resumption
  - 0-RTT packet building and processing
  - Early data acceptance and rejection handling
  - Server-side anti-replay protection
  - `ZeroRttAccepted` / `ZeroRttRejected` events
- **Documentation site** — GitHub Pages deployment with Bengal static site generator
  - Concept guides (sans-I/O, free-threading, HTTP/3, connection lifecycle)
  - Reference docs (connection, events, configuration)
  - Tutorials (echo server, quickstart)

### Security

- Use constant-time comparison (`hmac.compare_digest`) for TLS Finished message verification

## [0.2.0] - 2026-03-25

### Added

- **Loss recovery module** (`zoomies.recovery`) — RFC 9002 loss detection and congestion control
  - `SentPacket` registry and `PacketSpace` per-space tracking
  - `RttEstimator` with EWMA smoothing (RFC 9002 §5.3)
  - Packet-number and time-based loss detection with frame retransmission
  - PTO probing with exponential backoff
  - Anti-amplification enforcement (3x limit before address validation)
- **NewReno congestion controller** (RFC 9002 §7) — cwnd gating in send path
- **ACK generation** — track received packet numbers per space, emit ACK frames
- **Stream reassembly** — `Stream` class wired into connection for ordered delivery
- **Stream send offset tracking** via `StreamSendState.advance()`
- **HANDSHAKE_DONE frame** sent after handshake completes
- **CONNECTION_CLOSE frame** support
- **STOP_SENDING / RESET_STREAM** frame handling
- **Key update rotation** via HKDF "quic ku"
- **Variable packet-number length encoding**
- **Flow control enforcement** and idle timeout
- **Sans-I/O timer pattern** for loss detection callbacks
- **Benchmarks** — handshake latency and stream throughput (`benchmarks/`)
- **Comprehensive test coverage** — recovery integration, interop encrypt/decrypt roundtrip, Hypothesis property tests, connection hygiene, hardening

### Changed

- Consolidated HKDF into shared `crypto/_hkdf.py` module (used by both TLS and QUIC crypto)
- Consolidated `QUIC_VERSION_1` into `primitives/types.py`
- QPACK static table uses dict for O(1) lookup, bytes-native encode path
- AES-ECB cipher cached on `CryptoContext`, optimized nonce XOR
- Packet coalescing in `_flush_stream_send_queue`
- `bisect.insort` for stream chunks and crypto ranges
- Prune consumed crypto ranges, bytes-join instead of `+=`

### Fixed

- `InvalidTag` state corruption bug in crypto processing

## [0.1.1] - 2026-03-06

### Added

- `pull_destination_cid_for_routing()` in `zoomies.packet` — extract destination CID from QUIC datagram for connection routing (long/short headers)

## [0.1.0] - 2026-03-01

### Added

- Initial scaffolding: pyproject.toml, src layout, tests, docs
- Package structure: `zoomies`, `zoomies.core`, `zoomies.h3`, `zoomies.events`
- Placeholder `PlaceholderEvent` in events module
- CI workflow (tests, typecheck, lint)
- Pre-commit hooks (ruff, ty)
- Architecture design doc
