"""Tests for varint encoding (RFC 9000)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoomies.encoding import Buffer, pull_varint, push_varint
from zoomies.encoding.buffer import VARINT_MAX


@given(st.integers(min_value=0, max_value=VARINT_MAX))
def test_varint_roundtrip(value: int) -> None:
    """pull_varint(push_varint(x)) == x for all valid values."""
    buf = Buffer(capacity=8)
    push_varint(buf, value)
    buf.seek(0)
    assert pull_varint(buf) == value


def test_varint_1_byte() -> None:
    """Values 0-63 use 1 byte."""
    buf = Buffer(capacity=1)
    push_varint(buf, 0)
    assert buf.data == b"\x00"
    buf.seek(0)
    assert pull_varint(buf) == 0

    buf = Buffer(capacity=1)
    push_varint(buf, 63)
    assert buf.data == b"\x3f"
    buf.seek(0)
    assert pull_varint(buf) == 63


def test_varint_2_bytes() -> None:
    """Values 64-16383 use 2 bytes."""
    buf = Buffer(capacity=2)
    push_varint(buf, 64)
    assert buf.data == b"\x40\x40"
    buf.seek(0)
    assert pull_varint(buf) == 64


def test_varint_4_bytes() -> None:
    """Values 16384-1073741823 use 4 bytes."""
    buf = Buffer(capacity=4)
    push_varint(buf, 16384)
    buf.seek(0)
    assert pull_varint(buf) == 16384


def test_varint_8_bytes() -> None:
    """Values 1073741824+ use 8 bytes."""
    buf = Buffer(capacity=8)
    push_varint(buf, VARINT_MAX)
    buf.seek(0)
    assert pull_varint(buf) == VARINT_MAX


def test_varint_invalid_negative() -> None:
    """Negative value raises."""
    buf = Buffer(capacity=8)
    with pytest.raises(ValueError, match="Varint must be"):
        push_varint(buf, -1)


def test_varint_invalid_too_large() -> None:
    """Value > VARINT_MAX raises."""
    buf = Buffer(capacity=8)
    with pytest.raises(ValueError, match="Varint must be"):
        push_varint(buf, VARINT_MAX + 1)
