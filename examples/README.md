# Zoomies Examples

Run from repo root:

```bash
uv run python -m examples.qpack_roundtrip
uv run python -m examples.parse_initial_packet
uv run python -m examples.sans_io_connection
```

| Example | Description |
|---------|-------------|
| `qpack_roundtrip` | QPACK header encode/decode |
| `parse_initial_packet` | Parse QUIC Initial packet header |
| `sans_io_connection` | Sans-I/O `QuicConnection` demo (uses `tests/fixtures/` certs) |
