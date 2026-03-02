"""Adversarial tests — malformed input, truncated packets, invalid headers."""

import pytest

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.encoding import Buffer
from zoomies.encoding.buffer import BufferReadError
from zoomies.events import ConnectionClosed, DatagramReceived
from zoomies.frames import pull_ack_frame, pull_crypto_frame, pull_stream_frame
from zoomies.packet import pull_quic_header

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")


# --- 1.4 Connection datagram_received ---


def test_connection_short_datagram_returns_events() -> None:
    """len(data) < 7 returns events, no crash."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    events = conn.datagram_received(b"\x00" * 6, ("127.0.0.1", 443))
    assert len(events) == 1
    assert isinstance(events[0], DatagramReceived)
    assert events[0].data == b"\x00" * 6


def test_connection_invalid_header_connection_closed() -> None:
    """Malformed header triggers ConnectionClosed and state CLOSED."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    # Version negotiation (0x00000000) raises ValueError
    malformed = (
        b"\xc0\x00\x00\x00\x00"  # long, fixed, Initial; version 0
        b"\x08" + b"destcid8" + b"\x08" + b"srccid08"
    )
    events = conn.datagram_received(malformed, ("127.0.0.1", 443))
    closed = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(closed) == 1
    assert closed[0].reason == "Invalid header"
    assert conn._state.value == "closed"


def test_connection_oversized_cid_connection_closed() -> None:
    """Destination CID > 20 bytes triggers ConnectionClosed."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    # dest_cid_len=21 (0x15), need 21 bytes after
    malformed = (
        b"\xc0\x00\x00\x00\x01"  # long, fixed, Initial; version 1
        b"\x15" + b"x" * 21  # dest_cid_len 21, 21 bytes
    )
    events = conn.datagram_received(malformed, ("127.0.0.1", 443))
    closed = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(closed) == 1


# --- 1.3 Buffer edge cases ---


def test_buffer_push_uint8_out_of_range() -> None:
    """push_uint8(256) raises ValueError."""
    buf = Buffer(capacity=1)
    with pytest.raises(ValueError, match="uint8 must be 0-255"):
        buf.push_uint8(256)


def test_buffer_push_uint8_negative() -> None:
    """push_uint8(-1) raises ValueError."""
    buf = Buffer(capacity=1)
    with pytest.raises(ValueError, match="uint8 must be 0-255"):
        buf.push_uint8(-1)


def test_buffer_push_uint16_out_of_range() -> None:
    """push_uint16(0x10000) raises ValueError."""
    buf = Buffer(capacity=4)
    with pytest.raises(ValueError, match="uint16 must be 0-65535"):
        buf.push_uint16(0x10000)


def test_buffer_push_uint32_out_of_range() -> None:
    """push_uint32 out of range raises ValueError."""
    buf = Buffer(capacity=8)
    with pytest.raises(ValueError, match="uint32 out of range"):
        buf.push_uint32(0x1_0000_0000)


def test_buffer_push_uint64_out_of_range() -> None:
    """push_uint64 out of range raises ValueError."""
    buf = Buffer(capacity=16)
    with pytest.raises(ValueError, match="uint64 out of range"):
        buf.push_uint64(0x1_0000_0000_0000_0000)


def test_buffer_pull_bytes_past_eof() -> None:
    """pull_bytes(n) past EOF raises BufferReadError."""
    buf = Buffer(data=b"ab")
    buf.pull_bytes(2)
    with pytest.raises(BufferReadError, match="out of bounds"):
        buf.pull_bytes(1)


def test_buffer_seek_negative() -> None:
    """seek(-1) raises BufferReadError."""
    buf = Buffer(data=b"ab")
    with pytest.raises(BufferReadError, match="out of bounds"):
        buf.seek(-1)


def test_buffer_seek_past_end() -> None:
    """seek past end raises BufferReadError."""
    buf = Buffer(data=b"ab")
    with pytest.raises(BufferReadError, match="out of bounds"):
        buf.seek(100)


# --- 1.1 Packet header parsing ---


def test_header_truncated_empty() -> None:
    """Empty buffer raises BufferReadError."""
    buf = Buffer(data=b"")
    with pytest.raises(BufferReadError):
        pull_quic_header(buf)


def test_header_truncated_initial() -> None:
    """Truncated Initial header raises."""
    buf = Buffer(data=b"\xc0\x00\x00\x00\x01")  # long, version 1, no more
    with pytest.raises((BufferReadError, ValueError)):
        pull_quic_header(buf)


def test_header_invalid_version_negotiation() -> None:
    """Version 0 (negotiation) raises ValueError."""
    buf = Buffer(data=b"\xc0\x00\x00\x00\x00\x08" + b"destcid8" + b"\x08" + b"srccid08")
    with pytest.raises(ValueError, match="Version Negotiation"):
        pull_quic_header(buf)


def test_header_oversized_dest_cid() -> None:
    """Destination CID > 20 raises ValueError."""
    buf = Buffer(
        data=b"\xc0\x00\x00\x00\x01\x15" + b"x" * 21  # dest_cid_len 21
    )
    with pytest.raises(ValueError, match="Destination CID too long"):
        pull_quic_header(buf)


def test_header_oversized_src_cid() -> None:
    """Source CID > 20 raises ValueError."""
    buf = Buffer(
        data=(
            b"\xc0\x00\x00\x00\x01\x08" + b"destcid8\x15" + b"y" * 21  # src_cid_len 21
        )
    )
    with pytest.raises(ValueError, match="Source CID too long"):
        pull_quic_header(buf)


def test_header_short_requires_host_cid_length() -> None:
    """Short header with host_cid_length=None raises ValueError."""
    # 0x41 = short, fixed, pn_len=2; 8 bytes dcid; 2 bytes pn
    buf = Buffer(data=b"\x41" + b"12345678" + b"\x00\x2a")
    with pytest.raises(ValueError, match="host_cid_length"):
        pull_quic_header(buf, host_cid_length=None)


# --- 1.2 Frame parsing ---


def test_ack_frame_truncated() -> None:
    """Truncated ACK frame raises BufferReadError or ValueError."""
    buf = Buffer(data=b"\x02")  # ACK type byte consumed by caller; this is payload
    # pull_ack_frame expects: largest, delay, ack_range_count, first_ack_range
    with pytest.raises((BufferReadError, ValueError)):
        pull_ack_frame(buf)


def test_stream_frame_truncated() -> None:
    """Truncated STREAM frame (offset+len, no data) raises BufferReadError."""
    # 0x0e = stream with offset+len, no fin; stream_id=8, offset=1, length=2; no data bytes
    buf = Buffer(data=b"\x0e\x08\x01\x02")
    with pytest.raises(BufferReadError):
        pull_stream_frame(buf)


def test_crypto_frame_truncated() -> None:
    """Truncated CRYPTO frame (offset 0, length 10, no data) raises BufferReadError."""
    buf = Buffer(data=b"\x06\x00\x0a")  # type 6, offset 0, length 10; 0 bytes data
    with pytest.raises(BufferReadError):
        pull_crypto_frame(buf)
