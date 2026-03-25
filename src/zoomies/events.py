"""Protocol event types — frozen dataclasses for QUIC and HTTP/3.

Sans-I/O: protocol handlers produce these events. No I/O, no side effects.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DatagramReceived:
    """Raw datagram received from peer."""

    data: bytes
    addr: tuple[str, int]


@dataclass(frozen=True, slots=True)
class StreamDataReceived:
    """Stream data delivered to application."""

    stream_id: int
    data: bytes
    end_stream: bool
    is_0rtt: bool = False


@dataclass(frozen=True, slots=True)
class ConnectionClosed:
    """Connection closed by peer or locally."""

    error_code: int
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class HandshakeComplete:
    """QUIC handshake completed successfully."""


@dataclass(frozen=True, slots=True)
class ConnectionIdIssued:
    """New connection ID issued to peer."""

    connection_id: bytes
    retire_prior_to: int


@dataclass(frozen=True, slots=True)
class ConnectionIdRetired:
    """Connection ID retired by peer."""

    connection_id: bytes


@dataclass(frozen=True, slots=True)
class DecryptionFailed:
    """Packet decryption failed (InvalidTag). Informational — no state change."""

    packet_type: str


@dataclass(frozen=True, slots=True)
class StreamReset:
    """Peer reset a stream (RESET_STREAM frame)."""

    stream_id: int
    error_code: int
    final_size: int


@dataclass(frozen=True, slots=True)
class StopSendingReceived:
    """Peer requested we stop sending on a stream (STOP_SENDING frame)."""

    stream_id: int
    error_code: int


@dataclass(frozen=True, slots=True)
class H3HeadersReceived:
    """HTTP/3 headers received (e.g. request or response)."""

    stream_id: int
    headers: list[tuple[bytes, bytes]]
    end_stream: bool
    is_0rtt: bool = False


@dataclass(frozen=True, slots=True)
class H3DataReceived:
    """HTTP/3 data received on stream."""

    stream_id: int
    data: bytes
    end_stream: bool


# Union type for all QUIC events
QuicEvent = (
    DatagramReceived
    | StreamDataReceived
    | ConnectionClosed
    | HandshakeComplete
    | ConnectionIdIssued
    | ConnectionIdRetired
    | DecryptionFailed
    | StreamReset
    | StopSendingReceived
)

# Union type for HTTP/3 events
H3Event = H3HeadersReceived | H3DataReceived
