"""CRYPTO frame tests (RFC 9000 19.6)."""

import pytest

from zoomies.encoding import Buffer
from zoomies.frames import CryptoFrame, pull_crypto_frame, push_crypto_frame


def test_crypto_frame_roundtrip() -> None:
    """Push then pull yields identical frame."""
    frame = CryptoFrame(offset=0, data=b"hello")
    out = Buffer()
    push_crypto_frame(out, frame)
    buf = Buffer(data=out.data)
    parsed = pull_crypto_frame(buf)
    assert parsed == frame


def test_crypto_frame_roundtrip_with_offset() -> None:
    """CRYPTO frame with non-zero offset."""
    frame = CryptoFrame(offset=100, data=b"x" * 50)
    out = Buffer()
    push_crypto_frame(out, frame)
    buf = Buffer(data=out.data)
    parsed = pull_crypto_frame(buf)
    assert parsed.offset == 100
    assert parsed.data == b"x" * 50


def test_crypto_frame_bytes_match_roundtrip() -> None:
    """Push then pull yields identical bytes."""
    frame = CryptoFrame(offset=0, data=b"\x16\x03\x01\x00\x00")
    out = Buffer()
    push_crypto_frame(out, frame)
    buf = Buffer(data=out.data)
    parsed = pull_crypto_frame(buf)
    out2 = Buffer()
    push_crypto_frame(out2, parsed)
    assert out2.data == out.data


def test_not_crypto_frame_raises() -> None:
    """Wrong frame type raises."""
    buf = Buffer(data=bytes([0x01]))  # PING
    with pytest.raises(ValueError, match="Not a CRYPTO frame"):
        pull_crypto_frame(buf)
