"""Protocol event types — frozen dataclasses for QUIC and HTTP/3.

Sans-I/O: protocol handlers produce these events. No I/O, no side effects.
"""

from dataclasses import dataclass

from zoomies.crypto.tls import SessionTicket


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
class ZeroRttAccepted:
    """Server accepted 0-RTT early data."""


@dataclass(frozen=True, slots=True)
class ZeroRttRejected:
    """Server rejected 0-RTT early data. Streams will be resent as 1-RTT."""


@dataclass(frozen=True, slots=True)
class NewSessionTicket:
    """Server issued a session ticket for TLS 1.3 resumption and 0-RTT.

    Emitted on the client side after the handshake when the server sends
    a NewSessionTicket message. The caller should store the ticket and
    pass it via ``QuicConfiguration.session_ticket`` on reconnection.
    """

    ticket: SessionTicket


@dataclass(frozen=True, slots=True)
class RetryReceived:
    """Server sent Retry — client will resend Initial with token."""

    retry_source_cid: bytes


@dataclass(frozen=True, slots=True)
class PacketDropped:
    """Diagnostic: a received datagram was dropped without processing.

    Not a protocol error — just informational. Useful for debugging
    connection stalls and silent failures.
    """

    reason: str


@dataclass(frozen=True, slots=True)
class ConnectionMigrated:
    """Peer migrated to a new address (path validation succeeded)."""

    old_addr: tuple[str, int]
    new_addr: tuple[str, int]


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
    | ZeroRttAccepted
    | ZeroRttRejected
    | NewSessionTicket
    | RetryReceived
    | PacketDropped
    | ConnectionMigrated
)

# Union type for HTTP/3 events
H3Event = H3HeadersReceived | H3DataReceived
