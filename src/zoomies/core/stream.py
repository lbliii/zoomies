"""QUIC stream receive/send state - reassembly, FIN, flow control (RFC 9000 2-3)."""

from dataclasses import dataclass, field

from zoomies.frames.stream import StreamFrame
from zoomies.primitives import StreamId


@dataclass(slots=True)
class StreamReceiveState:
    """Receive state for a single stream.

    Buffers out-of-order STREAM frames and delivers contiguous data in order.
    """

    stream_id: StreamId
    _chunks: list[tuple[int, bytes]] = field(default_factory=list)
    _delivered_end: int = 0
    _fin_at: int | None = None
    _max_stream_data: int = 0

    def add_frame(self, frame: StreamFrame) -> bytes:
        """Add STREAM frame data. Returns newly deliverable contiguous bytes."""
        if frame.stream_id != self.stream_id:
            raise ValueError("Stream ID mismatch")
        offset = frame.offset
        data = frame.data
        if not data and not frame.fin:
            return b""
        if frame.fin:
            self._fin_at = offset + len(data)
        if data:
            self._chunks.append((offset, data))
            self._chunks.sort(key=lambda c: c[0])
        return self._deliver_contiguous()

    def _deliver_contiguous(self) -> bytes:
        """Extract contiguous bytes from delivered_end, advance, return."""
        result: list[bytes] = []
        i = 0
        while i < len(self._chunks):
            off, data = self._chunks[i]
            if off > self._delivered_end:
                break
            end = off + len(data)
            if end <= self._delivered_end:
                self._chunks.pop(i)
                continue
            start_in_chunk = self._delivered_end - off
            deliver = data[start_in_chunk:]
            result.append(deliver)
            self._delivered_end = end
            self._chunks.pop(i)
        return b"".join(result)

    @property
    def is_complete(self) -> bool:
        """True if FIN received and all data up to FIN delivered."""
        if self._fin_at is None:
            return False
        return self._delivered_end >= self._fin_at

    @property
    def bytes_delivered(self) -> int:
        return self._delivered_end

    def set_max_stream_data(self, limit: int) -> None:
        self._max_stream_data = limit

    def flow_control_ok(self, offset: int, length: int) -> bool:
        """Check if receiving this range is within flow control limit."""
        if self._max_stream_data <= 0:
            return True
        return offset + length <= self._max_stream_data


@dataclass(slots=True)
class StreamSendState:
    """Send state for a single stream."""

    stream_id: StreamId
    _sent_end: int = 0
    _fin_sent: bool = False
    _max_stream_data: int = 0

    @property
    def sent_end(self) -> int:
        return self._sent_end

    @property
    def fin_sent(self) -> bool:
        return self._fin_sent

    def advance(self, length: int, fin: bool = False) -> None:
        self._sent_end += length
        if fin:
            self._fin_sent = True

    def set_max_stream_data(self, limit: int) -> None:
        self._max_stream_data = limit

    def flow_control_ok(self, length: int) -> bool:
        if self._max_stream_data <= 0:
            return True
        return self._sent_end + length <= self._max_stream_data


class Stream:
    """Stream manager — receive buffers, FIN, flow control."""

    def __init__(self, stream_id: StreamId) -> None:
        self.stream_id = stream_id
        self._recv = StreamReceiveState(stream_id=stream_id)
        self._send = StreamSendState(stream_id=stream_id)

    def add_receive_frame(self, frame: StreamFrame) -> bytes:
        """Add received STREAM frame. Returns deliverable contiguous bytes."""
        return self._recv.add_frame(frame)

    @property
    def receive_complete(self) -> bool:
        return self._recv.is_complete

    @property
    def bytes_delivered(self) -> int:
        return self._recv.bytes_delivered

    def set_max_stream_data(self, limit: int) -> None:
        self._recv.set_max_stream_data(limit)
        self._send.set_max_stream_data(limit)
