"""STREAM frame (RFC 9000 19.8)."""

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
