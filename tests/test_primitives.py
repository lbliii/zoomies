"""Tests for protocol primitives."""

import pytest

from zoomies.primitives import (
    ConnectionId,
    FrameType,
    PacketNumber,
    PacketNumberSpace,
    PacketType,
    StreamId,
)
from zoomies.primitives.types import (
    CONNECTION_ID_MAX_LEN,
    PACKET_NUMBER_MAX,
    STREAM_ID_MAX,
)


class TestConnectionId:
    def test_valid_empty(self) -> None:
        cid = ConnectionId(value=b"")
        assert cid.value == b""

    def test_valid_8_bytes(self) -> None:
        cid = ConnectionId(value=b"12345678")
        assert cid.value == b"12345678"

    def test_valid_max_length(self) -> None:
        cid = ConnectionId(value=b"x" * CONNECTION_ID_MAX_LEN)
        assert len(cid.value) == CONNECTION_ID_MAX_LEN

    def test_invalid_too_long(self) -> None:
        with pytest.raises(ValueError, match="must be 0-20 bytes"):
            ConnectionId(value=b"x" * (CONNECTION_ID_MAX_LEN + 1))

    def test_immutable(self) -> None:
        cid = ConnectionId(value=b"abc")
        with pytest.raises(AttributeError):
            cid.value = b"xyz"  # type: ignore[misc]


class TestStreamId:
    def test_valid_zero(self) -> None:
        sid = StreamId(value=0)
        assert sid.value == 0

    def test_valid_max(self) -> None:
        sid = StreamId(value=STREAM_ID_MAX)
        assert sid.value == STREAM_ID_MAX

    def test_invalid_negative(self) -> None:
        with pytest.raises(ValueError, match="must be 0-"):
            StreamId(value=-1)

    def test_invalid_too_large(self) -> None:
        with pytest.raises(ValueError, match="must be 0-"):
            StreamId(value=STREAM_ID_MAX + 1)

    def test_immutable(self) -> None:
        sid = StreamId(value=1)
        with pytest.raises(AttributeError):
            sid.value = 2  # type: ignore[misc]


class TestPacketNumber:
    def test_valid_zero(self) -> None:
        pn = PacketNumber(value=0)
        assert pn.value == 0

    def test_valid_max(self) -> None:
        pn = PacketNumber(value=PACKET_NUMBER_MAX)
        assert pn.value == PACKET_NUMBER_MAX

    def test_invalid_negative(self) -> None:
        with pytest.raises(ValueError, match="must be 0-"):
            PacketNumber(value=-1)

    def test_invalid_too_large(self) -> None:
        with pytest.raises(ValueError, match="must be 0-"):
            PacketNumber(value=PACKET_NUMBER_MAX + 1)


class TestFrameType:
    def test_values(self) -> None:
        assert FrameType.PADDING == 0x00
        assert FrameType.PING == 0x01
        assert FrameType.ACK == 0x02
        assert FrameType.STREAM == 0x08


class TestPacketType:
    def test_values(self) -> None:
        assert PacketType.INITIAL == 0
        assert PacketType.HANDSHAKE == 2
        assert PacketType.ONE_RTT == 4


class TestPacketNumberSpace:
    def test_values(self) -> None:
        assert PacketNumberSpace.INITIAL == "initial"
        assert PacketNumberSpace.HANDSHAKE == "handshake"
        assert PacketNumberSpace.APPLICATION == "application"
