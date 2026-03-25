# Changelog

All notable changes to Zoomies will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
