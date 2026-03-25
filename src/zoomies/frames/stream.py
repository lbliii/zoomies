"""STREAM, STOP_SENDING, RESET_STREAM frames (RFC 9000 19.4, 19.5, 19.8)."""

from dataclasses import dataclass

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint, push_varint
from zoomies.primitives import StreamId


@dataclass(frozen=True, slots=True)
class StreamFrame:
    """STREAM frame — stream data with optional offset and FIN."""

    stream_id: StreamId
    offset: int
    data: bytes
    fin: bool


def pull_stream_frame(buf: Buffer) -> StreamFrame:
    """Parse STREAM frame. RFC 9000 19.8: Type, Stream ID, [Offset], [Length], Data."""
    frame_type = pull_varint(buf)
    if (frame_type & 0x08) != 0x08:
        raise ValueError("Not a STREAM frame")
    stream_id = StreamId(value=pull_varint(buf))
    off_bit = bool(frame_type & 0x04)
    len_bit = bool(frame_type & 0x02)
    fin = bool(frame_type & 0x01)
    offset = pull_varint(buf) if off_bit else 0
    length = pull_varint(buf) if len_bit else None
    if length is not None:
        data = buf.pull_bytes(length)
    else:
        data = buf.pull_bytes(len(buf.data) - buf.tell())
    return StreamFrame(stream_id=stream_id, offset=offset, data=data, fin=fin)


def push_stream_frame(buf: Buffer, frame: StreamFrame) -> None:
    """Serialize STREAM frame to buffer."""
    off_bit = 0x04 if frame.offset > 0 else 0
    len_bit = 0x02
    fin_bit = 0x01 if frame.fin else 0
    frame_type = 0x08 | off_bit | len_bit | fin_bit
    push_varint(buf, frame_type)
    push_varint(buf, frame.stream_id.value)
    if frame.offset > 0:
        push_varint(buf, frame.offset)
    push_varint(buf, len(frame.data))
    buf.push_bytes(frame.data)


# --- RESET_STREAM (RFC 9000 19.4) ---


@dataclass(frozen=True, slots=True)
class ResetStreamFrame:
    """RESET_STREAM frame — abruptly terminate sending on a stream."""

    stream_id: StreamId
    error_code: int
    final_size: int


def pull_reset_stream_frame(buf: Buffer) -> ResetStreamFrame:
    """Parse RESET_STREAM frame (type 0x04)."""
    frame_type = pull_varint(buf)
    if frame_type != 0x04:
        raise ValueError("Not a RESET_STREAM frame")
    stream_id = StreamId(value=pull_varint(buf))
    error_code = pull_varint(buf)
    final_size = pull_varint(buf)
    return ResetStreamFrame(stream_id=stream_id, error_code=error_code, final_size=final_size)


def push_reset_stream_frame(buf: Buffer, frame: ResetStreamFrame) -> None:
    """Serialize RESET_STREAM frame."""
    push_varint(buf, 0x04)
    push_varint(buf, frame.stream_id.value)
    push_varint(buf, frame.error_code)
    push_varint(buf, frame.final_size)


# --- STOP_SENDING (RFC 9000 19.5) ---


@dataclass(frozen=True, slots=True)
class StopSendingFrame:
    """STOP_SENDING frame — request peer to stop sending on a stream."""

    stream_id: StreamId
    error_code: int


def pull_stop_sending_frame(buf: Buffer) -> StopSendingFrame:
    """Parse STOP_SENDING frame (type 0x05)."""
    frame_type = pull_varint(buf)
    if frame_type != 0x05:
        raise ValueError("Not a STOP_SENDING frame")
    stream_id = StreamId(value=pull_varint(buf))
    error_code = pull_varint(buf)
    return StopSendingFrame(stream_id=stream_id, error_code=error_code)


def push_stop_sending_frame(buf: Buffer, frame: StopSendingFrame) -> None:
    """Serialize STOP_SENDING frame."""
    push_varint(buf, 0x05)
    push_varint(buf, frame.stream_id.value)
    push_varint(buf, frame.error_code)
