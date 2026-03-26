# Zoomies Examples

Run from repo root:

```bash
uv run python -m examples.qpack_roundtrip
uv run python -m examples.parse_initial_packet
uv run python -m examples.sans_io_connection
uv run python -m examples.h3_server_loop
uv run python -m examples.stream_echo
```

| Example | Description |
|---------|-------------|
| `qpack_roundtrip` | QPACK header encode/decode |
| `parse_initial_packet` | Parse QUIC Initial packet header |
| `sans_io_connection` | Sans-I/O `QuicConnection` demo (uses `tests/fixtures/` certs) |
| `h3_server_loop` | Pounce-style H3 loop: datagram → events → handle_event → send_headers/send_data → send_datagrams |
| `stream_echo` | 0.2.0 features: stream reassembly, RTT estimation, congestion control, loss detection, PTO timer loop |
