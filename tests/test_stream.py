"""Stream receive/send state — reorder frames, FIN, flow control."""

from zoomies.core import Stream, StreamReceiveState, StreamSendState
from zoomies.frames.stream import StreamFrame
from zoomies.primitives import StreamId


def test_stream_receive_in_order() -> None:
    """In-order frames deliver immediately."""
    recv = StreamReceiveState(stream_id=StreamId(value=0))
    d1 = recv.add_frame(
        StreamFrame(stream_id=StreamId(value=0), offset=0, data=b"hello", fin=False)
    )
    assert d1 == b"hello"
    d2 = recv.add_frame(
        StreamFrame(stream_id=StreamId(value=0), offset=5, data=b" world", fin=True)
    )
    assert d2 == b" world"
    assert recv.is_complete
    assert recv.bytes_delivered == 11


def test_stream_receive_out_of_order() -> None:
    """Out-of-order frames buffer and deliver when contiguous."""
    recv = StreamReceiveState(stream_id=StreamId(value=4))
    # Receive offset 5 first
    d1 = recv.add_frame(
        StreamFrame(stream_id=StreamId(value=4), offset=5, data=b" world", fin=False)
    )
    assert d1 == b""
    assert recv.bytes_delivered == 0
    # Receive offset 0
    d2 = recv.add_frame(
        StreamFrame(stream_id=StreamId(value=4), offset=0, data=b"hello", fin=False)
    )
    assert d2 == b"hello world"
    assert recv.bytes_delivered == 11


def test_stream_receive_fin_produces_complete() -> None:
    """FIN with data marks stream complete when all data delivered."""
    recv = StreamReceiveState(stream_id=StreamId(value=0))
    recv.add_frame(StreamFrame(stream_id=StreamId(value=0), offset=0, data=b"x", fin=True))
    assert recv.is_complete
    assert recv.bytes_delivered == 1


def test_stream_receive_fin_with_gap() -> None:
    """FIN sets final offset; complete only when gap filled."""
    recv = StreamReceiveState(stream_id=StreamId(value=0))
    recv.add_frame(StreamFrame(stream_id=StreamId(value=0), offset=5, data=b"!", fin=True))
    assert not recv.is_complete
    recv.add_frame(StreamFrame(stream_id=StreamId(value=0), offset=0, data=b"hello", fin=False))
    assert recv.is_complete
    assert recv.bytes_delivered == 6


def test_stream_manager_add_frame() -> None:
    """Stream.add_receive_frame returns deliverable bytes."""
    s = Stream(stream_id=StreamId(value=8))
    d = s.add_receive_frame(
        StreamFrame(stream_id=StreamId(value=8), offset=0, data=b"abc", fin=True)
    )
    assert d == b"abc"
    assert s.receive_complete
    assert s.bytes_delivered == 3


def test_stream_manager_reorder() -> None:
    """Stream reassembles out-of-order frames."""
    s = Stream(stream_id=StreamId(value=2))
    s.add_receive_frame(StreamFrame(stream_id=StreamId(value=2), offset=3, data=b"def", fin=False))
    d = s.add_receive_frame(
        StreamFrame(stream_id=StreamId(value=2), offset=0, data=b"abc", fin=False)
    )
    assert d == b"abcdef"
    s.add_receive_frame(StreamFrame(stream_id=StreamId(value=2), offset=6, data=b"", fin=True))
    assert s.receive_complete


def test_stream_send_state_advance() -> None:
    """StreamSendState tracks sent offset and FIN."""
    send = StreamSendState(stream_id=StreamId(value=0))
    assert send.sent_end == 0
    assert not send.fin_sent
    send.advance(5, fin=False)
    assert send.sent_end == 5
    send.advance(3, fin=True)
    assert send.sent_end == 8
    assert send.fin_sent


def test_stream_flow_control() -> None:
    """Flow control limits can be set and checked."""
    recv = StreamReceiveState(stream_id=StreamId(value=0))
    recv.set_max_stream_data(10)
    assert recv.flow_control_ok(0, 10)
    assert not recv.flow_control_ok(0, 11)
    assert recv.flow_control_ok(5, 5)
