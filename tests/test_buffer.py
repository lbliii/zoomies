"""Tests for Buffer."""

import pytest

from zoomies.encoding import Buffer
from zoomies.encoding.buffer import BufferReadError


def test_buffer_from_data() -> None:
    """Buffer(data=...) initializes from bytes."""
    buf = Buffer(data=b"hello")
    assert buf.data == b"hello"
    assert buf.tell() == 0


def test_buffer_pull_bytes() -> None:
    """pull_bytes advances position."""
    buf = Buffer(data=b"abc")
    assert buf.pull_bytes(2) == b"ab"
    assert buf.tell() == 2
    assert buf.pull_bytes(1) == b"c"
    assert buf.eof()


def test_buffer_pull_uint8() -> None:
    """pull_uint8 reads single byte."""
    buf = Buffer(data=b"\xff\x00")
    assert buf.pull_uint8() == 255
    assert buf.pull_uint8() == 0


def test_buffer_pull_uint16() -> None:
    """pull_uint16 reads big-endian."""
    buf = Buffer(data=b"\x12\x34")
    assert buf.pull_uint16() == 0x1234


def test_buffer_pull_uint32() -> None:
    """pull_uint32 reads big-endian."""
    buf = Buffer(data=b"\x12\x34\x56\x78")
    assert buf.pull_uint32() == 0x12345678


def test_buffer_pull_uint64() -> None:
    """pull_uint64 reads big-endian."""
    buf = Buffer(data=b"\x12\x34\x56\x78\x9a\xbc\xde\xf0")
    assert buf.pull_uint64() == 0x123456789ABCDEF0


def test_buffer_read_error() -> None:
    """Read past end raises BufferReadError."""
    buf = Buffer(data=b"ab")
    buf.pull_bytes(2)
    with pytest.raises(BufferReadError, match="out of bounds"):
        buf.pull_bytes(1)


def test_buffer_push_bytes() -> None:
    """push_bytes appends."""
    buf = Buffer(capacity=10)
    buf.push_bytes(b"hi")
    assert buf.data == b"hi"


def test_buffer_push_uint8() -> None:
    """push_uint8 appends 1 byte."""
    buf = Buffer(capacity=1)
    buf.push_uint8(42)
    assert buf.data == b"\x2a"


def test_buffer_push_uint16() -> None:
    """push_uint16 appends big-endian."""
    buf = Buffer(capacity=2)
    buf.push_uint16(0x1234)
    assert buf.data == b"\x12\x34"


def test_buffer_data_slice() -> None:
    """data_slice returns slice without advancing."""
    buf = Buffer(data=b"hello")
    assert buf.data_slice(0, 3) == b"hel"
    assert buf.tell() == 0


def test_buffer_seek() -> None:
    """seek sets position."""
    buf = Buffer(data=b"abc")
    buf.seek(2)
    assert buf.tell() == 2
    assert buf.pull_bytes(1) == b"c"


def test_buffer_seek_out_of_bounds() -> None:
    """Seek past end raises."""
    buf = Buffer(data=b"ab")
    with pytest.raises(BufferReadError, match="out of bounds"):
        buf.seek(3)


def test_buffer_pull_uint_var() -> None:
    """pull_uint_var / push_uint_var round-trip."""
    buf = Buffer(capacity=8)
    buf.push_uint_var(12345)
    buf.seek(0)
    assert buf.pull_uint_var() == 12345
