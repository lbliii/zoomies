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
H3_FRAME_SETTINGS = 0x04

# RFC 9114 SS7.2.4.1: HTTP/3 settings
SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06
SETTINGS_QPACK_BLOCKED_STREAMS = 0x07

# RFC 9204 SS4.2: Unidirectional stream types
H3_STREAM_TYPE_CONTROL = 0x00
H3_STREAM_TYPE_ENCODER = 0x02
H3_STREAM_TYPE_DECODER = 0x03


class H3StreamSender(Protocol):
    """Protocol for sending H3 stream data into the QUIC layer."""

    def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool) -> None: ...


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


def encode_settings(settings: dict[int, int]) -> bytes:
    """Encode an H3 SETTINGS frame payload."""
    buf = Buffer()
    for setting_id, value in settings.items():
        push_varint(buf, setting_id)
        push_varint(buf, value)
    return buf.data


def decode_settings(data: bytes) -> dict[int, int]:
    """Decode an H3 SETTINGS frame payload."""
    buf = Buffer(data=data)
    settings: dict[int, int] = {}
    while not buf.eof():
        setting_id = pull_varint(buf)
        value = pull_varint(buf)
        settings[setting_id] = value
    return settings


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
        qpack_blocked_streams: int = 0,
    ) -> None:
        self._stream_buffers: dict[int, bytearray] = {}
        self._sender = sender
        self._qpack_max_table_capacity = qpack_max_table_capacity
        self._qpack_blocked_streams = qpack_blocked_streams
        self._peer_settings: dict[int, int] | None = None
        self._settings_sent = False

        # Uni stream type tracking: stream_id -> stream_type
        self._uni_stream_types: dict[int, int] = {}

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

    @property
    def peer_settings(self) -> dict[int, int] | None:
        return self._peer_settings

    def local_settings(self) -> dict[int, int]:
        """Return the SETTINGS this connection advertises."""
        settings: dict[int, int] = {}
        if self._qpack_max_table_capacity > 0:
            settings[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = self._qpack_max_table_capacity
        if self._qpack_blocked_streams > 0:
            settings[SETTINGS_QPACK_BLOCKED_STREAMS] = self._qpack_blocked_streams
        return settings

    def settings_data(self) -> bytes | None:
        """Return SETTINGS frame bytes to send on the control stream.

        Returns None if already sent or if there are no settings to send.
        Call once after construction; the frame includes the control stream
        type prefix (varint 0x00).
        """
        if self._settings_sent:
            return None
        self._settings_sent = True
        settings = self.local_settings()
        payload = encode_settings(settings)
        # Control stream: stream type (varint 0x00) + SETTINGS frame
        buf = Buffer()
        push_varint(buf, H3_STREAM_TYPE_CONTROL)
        buf.push_bytes(_encode_frame(H3_FRAME_SETTINGS, payload))
        return buf.data

    def apply_peer_settings(self, settings: dict[int, int]) -> None:
        """Apply peer's SETTINGS to encoder capacity.

        If the peer advertises QPACK_MAX_TABLE_CAPACITY, the encoder
        capacity is set to min(local_max, peer_advertised). If peer
        advertises 0, the encoder stays static-only.
        """
        self._peer_settings = settings
        peer_capacity = settings.get(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0)
        if self._encoder is not None and peer_capacity > 0:
            effective = min(self._qpack_max_table_capacity, peer_capacity)
            self._encoder.set_capacity(effective)
        elif self._encoder is not None and peer_capacity == 0:
            # Peer doesn't support dynamic table
            self._encoder.set_capacity(0)

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
            enc_data = self._encoder.encoder_stream_data()
            if enc_data:
                self._sender.send_stream_data(H3_STREAM_TYPE_ENCODER, enc_data, False)
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
            elif frame_type == H3_FRAME_SETTINGS:
                self.apply_peer_settings(decode_settings(frame_data))
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
