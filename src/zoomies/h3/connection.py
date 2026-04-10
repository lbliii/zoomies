"""HTTP/3 connection -- receive H3 frames, emit H3HeadersReceived, H3DataReceived."""

from __future__ import annotations

from typing import Protocol

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint, push_varint
from zoomies.events import (
    H3DataReceived,
    H3Event,
    H3HeadersReceived,
    QuicEvent,
    StreamDataReceived,
)
from zoomies.h3.qpack import (
    QpackDecoder,
    QpackEncoder,
    decode_headers,
    encode_headers_from_bytes,
)

# RFC 9114: HTTP/3 frame types
H3_FRAME_DATA = 0x00
H3_FRAME_HEADERS = 0x01


class H3StreamSender(Protocol):
    """Protocol for sending H3 stream data into the QUIC layer. Implemented by QuicConnection."""

    def send_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool
    ) -> None: ...


def _encode_frame(frame_type: int, payload: bytes) -> bytes:
    """Encode H3 frame: type (varint) + length (varint) + payload."""
    buf = Buffer()
    push_varint(buf, frame_type)
    push_varint(buf, len(payload))
    buf.push_bytes(payload)
    return buf.data


def _parse_frame(buf: Buffer) -> tuple[int, bytes] | None:
    """Parse one H3 frame from buffer. Returns (type, payload) or None."""
    if buf.eof():
        return None
    try:
        frame_type = pull_varint(buf)
        length = pull_varint(buf)
        payload = buf.pull_bytes(length)
        return (frame_type, payload)
    except ValueError:
        return None


class H3Connection:
    """HTTP/3 connection -- parses H3 frames from stream data, emits events.

    When ``qpack_max_table_capacity > 0``, a stateful QpackEncoder/QpackDecoder
    pair is used for header compression. Otherwise, falls back to stateless
    static-table-only encoding (backward compatible).
    """

    def __init__(
        self,
        sender: H3StreamSender | None = None,
        *,
        qpack_max_table_capacity: int = 0,
    ) -> None:
        self._stream_buffers: dict[int, bytearray] = {}
        self._sender = sender
        self._qpack_max_table_capacity = qpack_max_table_capacity

        if qpack_max_table_capacity > 0:
            self._encoder: QpackEncoder | None = QpackEncoder(
                max_table_capacity=qpack_max_table_capacity
            )
            self._decoder: QpackDecoder | None = QpackDecoder(
                max_table_capacity=qpack_max_table_capacity
            )
            self._encoder.set_capacity(qpack_max_table_capacity)
            self._decoder.set_capacity(qpack_max_table_capacity)
        else:
            self._encoder = None
            self._decoder = None

    @property
    def encoder(self) -> QpackEncoder | None:
        return self._encoder

    @property
    def decoder(self) -> QpackDecoder | None:
        return self._decoder

    def handle_event(self, event: QuicEvent) -> list[H3Event]:
        """Process QUIC event; returns H3 events for StreamDataReceived only."""
        if isinstance(event, StreamDataReceived):
            return self.stream_data_received(
                event.stream_id,
                event.data,
                event.end_stream,
                is_0rtt=event.is_0rtt,
            )
        return []

    def send_headers(
        self,
        stream_id: int,
        headers: list[tuple[bytes, bytes]],
        end_stream: bool = False,
    ) -> None:
        """Send HTTP/3 HEADERS frame. Requires sender in constructor."""
        if self._sender is None:
            raise RuntimeError("H3Connection needs sender for send_headers")

        if self._encoder is not None:
            payload = self._encoder.encode_from_bytes(headers)
            # Flush encoder stream instructions to sender
            enc_data = self._encoder.encoder_stream_data()
            if enc_data:
                self._sender.send_stream_data(
                    self._encoder_stream_id, enc_data, False
                )
        else:
            payload = encode_headers_from_bytes(headers)

        frame = _encode_frame(H3_FRAME_HEADERS, payload)
        self._sender.send_stream_data(stream_id, frame, end_stream)

    def send_data(
        self,
        stream_id: int,
        data: bytes,
        end_stream: bool = False,
    ) -> None:
        """Send HTTP/3 DATA frame. Requires sender in constructor."""
        if self._sender is None:
            raise RuntimeError("H3Connection needs sender for send_data")
        frame = _encode_frame(H3_FRAME_DATA, data)
        self._sender.send_stream_data(stream_id, frame, end_stream)

    def feed_encoder_stream(self, data: bytes) -> None:
        """Feed encoder stream data to the decoder."""
        if self._decoder is not None:
            self._decoder.feed_encoder_stream(data)

    def stream_data_received(
        self,
        stream_id: int,
        data: bytes,
        end_stream: bool,
        is_0rtt: bool = False,
    ) -> list[H3Event]:
        """Process stream data; returns H3 events."""
        events: list[H3Event] = []
        self._stream_buffers.setdefault(stream_id, bytearray()).extend(data)
        buf = self._stream_buffers[stream_id]

        while buf:
            b = Buffer(data=bytes(buf))
            parsed = _parse_frame(b)
            if parsed is None:
                break
            frame_type, frame_data = parsed
            consumed = b.tell()
            del buf[:consumed]

            if frame_type == H3_FRAME_HEADERS:
                if self._decoder is not None:
                    decoded = self._decoder.decode(frame_data)
                else:
                    decoded = decode_headers(frame_data)
                events.append(
                    H3HeadersReceived(
                        stream_id=stream_id,
                        headers=[h.as_bytes() for h in decoded],
                        end_stream=end_stream and len(buf) == 0,
                        is_0rtt=is_0rtt,
                    )
                )
            elif frame_type == H3_FRAME_DATA:
                events.append(
                    H3DataReceived(
                        stream_id=stream_id,
                        data=frame_data,
                        end_stream=end_stream and len(buf) == 0,
                    )
                )

        if end_stream and stream_id in self._stream_buffers:
            del self._stream_buffers[stream_id]

        return events

    # Encoder stream uses uni stream type 0x02 (RFC 9204 SS4.2)
    _encoder_stream_id: int = 0x02
