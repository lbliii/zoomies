"""HTTP/3 request/response parsing."""

import pytest

from zoomies.encoding import Buffer
from zoomies.encoding.varint import push_varint
from zoomies.events import H3DataReceived, H3HeadersReceived, StreamDataReceived
from zoomies.h3.connection import H3_FRAME_DATA, H3_FRAME_HEADERS, H3Connection
from zoomies.h3.qpack import Header, encode_headers


def _make_headers_frame(headers: list[Header]) -> bytes:
    """Build HEADERS frame bytes."""
    payload = encode_headers(headers)
    b = Buffer()
    push_varint(b, H3_FRAME_HEADERS)
    push_varint(b, len(payload))
    b.push_bytes(payload)
    return b.data


def _make_data_frame(data: bytes) -> bytes:
    """Build DATA frame bytes."""
    b = Buffer()
    push_varint(b, H3_FRAME_DATA)
    push_varint(b, len(data))
    b.push_bytes(data)
    return b.data


def test_h3_headers_received() -> None:
    """H3Connection emits H3HeadersReceived for HEADERS frame."""
    conn = H3Connection()
    headers = [Header(name=":method", value="GET"), Header(name=":path", value="/")]
    frame = _make_headers_frame(headers)
    events = conn.stream_data_received(stream_id=0, data=frame, end_stream=True)
    assert len(events) == 1
    assert isinstance(events[0], H3HeadersReceived)
    assert events[0].stream_id == 0
    names = [h[0] for h in events[0].headers]
    assert b":method" in names
    assert events[0].end_stream


def test_h3_data_received() -> None:
    """H3Connection emits H3DataReceived for DATA frame."""
    conn = H3Connection()
    frame = _make_data_frame(b"hello")
    events = conn.stream_data_received(stream_id=4, data=frame, end_stream=True)
    assert len(events) == 1
    assert isinstance(events[0], H3DataReceived)
    assert events[0].stream_id == 4
    assert events[0].data == b"hello"
    assert events[0].end_stream


def test_h3_request_parsing() -> None:
    """Parse HTTP/3 request (HEADERS + DATA)."""
    conn = H3Connection()
    headers = [
        Header(name=":method", value="GET"),
        Header(name=":path", value="/api"),
        Header(name=":scheme", value="https"),
    ]
    hframe = _make_headers_frame(headers)
    dframe = _make_data_frame(b"")
    data = hframe + dframe
    events = conn.stream_data_received(stream_id=0, data=data, end_stream=True)
    assert any(isinstance(e, H3HeadersReceived) for e in events)
    assert len(events) >= 1


def test_h3_handle_event_stream_data_received() -> None:
    """handle_event(StreamDataReceived) delegates to stream_data_received."""
    conn = H3Connection()
    headers = [Header(name=":method", value="GET"), Header(name=":path", value="/")]
    frame = _make_headers_frame(headers)
    event = StreamDataReceived(stream_id=0, data=frame, end_stream=True)
    events = conn.handle_event(event)
    assert len(events) == 1
    assert isinstance(events[0], H3HeadersReceived)
    assert events[0].stream_id == 0
    assert b":method" in [h[0] for h in events[0].headers]


def test_h3_handle_event_ignores_non_stream() -> None:
    """handle_event returns [] for non-StreamDataReceived events."""
    from zoomies.events import HandshakeComplete

    conn = H3Connection()
    events = conn.handle_event(HandshakeComplete())
    assert events == []


def test_h3_send_headers_via_mock_sender() -> None:
    """send_headers produces correct H3 frame bytes via mock sender."""
    sent: list[tuple[int, bytes, bool]] = []

    class MockSender:
        def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
            sent.append((stream_id, data, end_stream))

    conn = H3Connection(sender=MockSender())
    conn.send_headers(
        stream_id=4,
        headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
        end_stream=False,
    )
    assert len(sent) == 1
    assert sent[0][0] == 4
    assert sent[0][2] is False
    # Frame: type 0x01 (HEADERS) + length + QPACK payload
    frame = sent[0][1]
    buf = Buffer(data=frame)
    from zoomies.encoding.varint import pull_varint

    assert pull_varint(buf) == H3_FRAME_HEADERS
    payload_len = pull_varint(buf)
    payload = buf.pull_bytes(payload_len)
    assert len(payload) > 0  # QPACK-encoded headers


def test_h3_send_data_via_mock_sender() -> None:
    """send_data produces correct H3 frame bytes via mock sender."""
    sent: list[tuple[int, bytes, bool]] = []

    class MockSender:
        def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
            sent.append((stream_id, data, end_stream))

    conn = H3Connection(sender=MockSender())
    conn.send_data(stream_id=4, data=b"hello world", end_stream=True)
    assert len(sent) == 1
    assert sent[0][0] == 4
    assert sent[0][1].endswith(b"hello world")
    assert sent[0][2] is True


def test_h3_send_headers_requires_sender() -> None:
    """send_headers raises RuntimeError when sender is None."""
    conn = H3Connection()
    with pytest.raises(RuntimeError, match="sender"):
        conn.send_headers(stream_id=0, headers=[(b":status", b"200")])


def test_h3_send_data_requires_sender() -> None:
    """send_data raises RuntimeError when sender is None."""
    conn = H3Connection()
    with pytest.raises(RuntimeError, match="sender"):
        conn.send_data(stream_id=0, data=b"")
