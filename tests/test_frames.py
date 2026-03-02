"""Frame round-trip and parse tests (RFC 9000, aioquic patterns)."""

import pytest

from zoomies.encoding import Buffer
from zoomies.frames import (
    AckFrame,
    PaddingFrame,
    PingFrame,
    StreamFrame,
    pull_ack_frame,
    pull_padding_frame,
    pull_ping_frame,
    pull_stream_frame,
    push_ack_frame,
    push_padding_frame,
    push_ping_frame,
    push_stream_frame,
)
from zoomies.primitives import StreamId


def _roundtrip_push_pull(buf_data: bytes, pull_fn, push_fn, frame) -> None:
    """Push frame to buffer, then pull; verify bytes match."""
    out = Buffer()
    push_fn(out, frame)
    got = Buffer(data=out.data)
    parsed = pull_fn(got)
    assert parsed == frame


class TestAckFrame:
    def test_roundtrip_single_range(self) -> None:
        frame = AckFrame(ranges=(range(10, 15),), delay=0)
        out = Buffer()
        push_ack_frame(out, frame)
        buf = Buffer(data=out.data)
        parsed = pull_ack_frame(buf)
        assert parsed.ranges == frame.ranges
        assert parsed.delay == frame.delay

    def test_roundtrip_multiple_ranges(self) -> None:
        frame = AckFrame(ranges=(range(5, 8), range(10, 15)), delay=3)
        out = Buffer()
        push_ack_frame(out, frame)
        buf = Buffer(data=out.data)
        parsed = pull_ack_frame(buf)
        assert parsed.ranges == frame.ranges
        assert parsed.delay == frame.delay

    def test_ack_bytes_match_roundtrip(self) -> None:
        """Push then pull yields identical bytes."""
        frame = AckFrame(ranges=(range(100, 101),), delay=0)
        out = Buffer()
        push_ack_frame(out, frame)
        buf = Buffer(data=out.data)
        parsed = pull_ack_frame(buf)
        out2 = Buffer()
        push_ack_frame(out2, parsed)
        assert out2.data == out.data


class TestStreamFrame:
    def test_roundtrip_no_offset_no_fin(self) -> None:
        frame = StreamFrame(
            stream_id=StreamId(value=0),
            offset=0,
            data=b"hello",
            fin=False,
        )
        out = Buffer()
        push_stream_frame(out, frame)
        buf = Buffer(data=out.data)
        parsed = pull_stream_frame(buf)
        assert parsed == frame

    def test_roundtrip_with_offset_and_fin(self) -> None:
        frame = StreamFrame(
            stream_id=StreamId(value=4),
            offset=100,
            data=b"world",
            fin=True,
        )
        out = Buffer()
        push_stream_frame(out, frame)
        buf = Buffer(data=out.data)
        parsed = pull_stream_frame(buf)
        assert parsed == frame

    def test_roundtrip_large_stream_id(self) -> None:
        frame = StreamFrame(
            stream_id=StreamId(value=12345),
            offset=0,
            data=b"x",
            fin=False,
        )
        out = Buffer()
        push_stream_frame(out, frame)
        buf = Buffer(data=out.data)
        parsed = pull_stream_frame(buf)
        assert parsed == frame

    def test_not_stream_frame_raises(self) -> None:
        buf = Buffer(data=bytes([0x01]))  # PING
        with pytest.raises(ValueError, match="Not a STREAM frame"):
            pull_stream_frame(buf)


class TestPaddingFrame:
    def test_roundtrip(self) -> None:
        frame = PaddingFrame(length=5)
        out = Buffer()
        push_padding_frame(out, frame)
        assert out.data == bytes(5)
        buf = Buffer(data=out.data)
        parsed = pull_padding_frame(buf)
        assert parsed.length == 5

    def test_empty_padding(self) -> None:
        frame = PaddingFrame(length=0)
        out = Buffer()
        push_padding_frame(out, frame)
        assert out.data == b""
        buf = Buffer(data=out.data)
        parsed = pull_padding_frame(buf)
        assert parsed.length == 0


class TestPingFrame:
    def test_roundtrip(self) -> None:
        frame = PingFrame()
        out = Buffer()
        push_ping_frame(out, frame)
        assert out.data == bytes([0x01])
        buf = Buffer(data=out.data)
        parsed = pull_ping_frame(buf)
        assert parsed == frame

    def test_not_ping_raises(self) -> None:
        buf = Buffer(data=bytes([0x00]))
        with pytest.raises(ValueError, match="Not a PING frame"):
            pull_ping_frame(buf)
