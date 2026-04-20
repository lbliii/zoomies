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
    """Stream data delivered to application.

    Attributes:
        stream_id: QUIC stream identifier. Low two bits encode direction
            and initiator (RFC 9000 §2.1): bit 0 = client-initiated (0) /
            server-initiated (1); bit 1 = bidirectional (0) /
            unidirectional (1).
        data: Payload bytes, in-order. May be empty when ``end_stream``
            is True and the peer closed without sending data.
        end_stream: True when this chunk is the final STREAM frame
            (FIN bit set). After this, no more data will arrive for
            ``stream_id``.
        is_0rtt: True when the data arrived in a 0-RTT packet. REPLAY
            WARNING: 0-RTT data is not forward-secret and CAN be replayed
            by an attacker. Treat as untrusted and idempotent only (e.g.
            GET requests). Reject anything that mutates server state.
            Always False on clients.
    """

    stream_id: int
    data: bytes
    end_stream: bool
    is_0rtt: bool = False


@dataclass(frozen=True, slots=True)
class ConnectionClosed:
    """Connection closed by peer or locally.

    Attributes:
        error_code: QUIC transport error code (RFC 9000 §20.1) or
            application error code (RFC 9000 §20.2). ``0`` means no
            error (clean shutdown). Common transport codes: ``0x01``
            INTERNAL_ERROR, ``0x0a`` PROTOCOL_VIOLATION, ``0x0d``
            CRYPTO_BUFFER_EXCEEDED. Application codes live in a
            separate space and are protocol-defined (e.g. HTTP/3
            error codes in RFC 9114 §8.1).
        reason: Human-readable reason from the peer's CONNECTION_CLOSE
            frame. May be empty or None. Do NOT parse — surface to
            logs/UI only.
    """

    error_code: int
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class HandshakeComplete:
    """QUIC handshake completed successfully."""


@dataclass(frozen=True, slots=True)
class ConnectionIdIssued:
    """New connection ID issued to peer.

    Attributes:
        connection_id: The freshly issued CID bytes. Typically 8 bytes;
            the peer may route by any prefix.
        retire_prior_to: Sequence number below which the peer MUST
            retire all previously issued CIDs (RFC 9000 §19.15). A
            non-zero value here means the caller should stop routing
            any in-flight datagrams that still carry the old CIDs —
            otherwise decryption will silently fail after a migration.
    """

    connection_id: bytes
    retire_prior_to: int


@dataclass(frozen=True, slots=True)
class ConnectionIdRetired:
    """Connection ID retired by peer."""

    connection_id: bytes


@dataclass(frozen=True, slots=True)
class DecryptionFailed:
    """Packet decryption failed (InvalidTag). Informational — no state change.

    Attributes:
        packet_type: Packet space the failed packet belonged to. One of
            ``"initial"``, ``"handshake"``, ``"0rtt"``, ``"1rtt"``.
            Compare as a string literal — this is a tagged enum by
            convention, not a numeric code. A few of these during a
            migration or key update is benign; a flood on ``"1rtt"``
            indicates an on-path attacker, packet corruption, or a CID
            routing bug in the caller.
    """

    packet_type: str


@dataclass(frozen=True, slots=True)
class StreamReset:
    """Peer reset a stream (RESET_STREAM frame).

    Attributes:
        stream_id: The stream the peer abandoned.
        error_code: Application-defined error code the peer sent with
            RESET_STREAM. Meaning is protocol-specific (e.g. HTTP/3
            error codes in RFC 9114 §8.1).
        final_size: Total bytes the peer committed to sending on this
            stream before resetting (RFC 9000 §4.5). Used for
            connection-level flow control accounting. The application
            may have observed fewer bytes via ``StreamDataReceived``;
            the difference is lost data.
    """

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
    """Server sent Retry — client will resend Initial with token.

    Attributes:
        retry_source_cid: The Source Connection ID from the server's
            Retry packet (RFC 9000 §17.2.5). The client will use this
            as the Destination CID on its retried Initial, and the
            server binds the Retry token to this value. The library
            handles the resend automatically; surfaced here purely
            for diagnostics and address-validation logging.
    """

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
    """HTTP/3 headers received (e.g. request or response).

    Attributes:
        stream_id: QUIC stream carrying this HTTP/3 request or response.
        headers: Header list as ``(name, value)`` byte pairs. Names are
            lowercase (RFC 9114 §4.2). Pseudo-headers (``:method``,
            ``:status``, ``:path``, ``:authority``, ``:scheme``) come
            first, before regular headers, per RFC 9114 §4.3.
        end_stream: True when the HEADERS frame carried FIN — no body
            follows.
        is_0rtt: True when the request arrived on a 0-RTT packet.
            REPLAY WARNING: reject non-idempotent methods (POST, PUT,
            DELETE, PATCH) when this is True. Only GET/HEAD/OPTIONS
            are safe to process on 0-RTT. Always False on clients.
    """

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
type QuicEvent = (
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
type H3Event = H3HeadersReceived | H3DataReceived
