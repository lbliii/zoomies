"""Sent packet metadata for loss detection and retransmission (RFC 9002)."""

from dataclasses import dataclass
from enum import StrEnum


class PacketNumberSpace(StrEnum):
    """QUIC packet number spaces (RFC 9002 §A.2)."""

    INITIAL = "initial"
    HANDSHAKE = "handshake"
    APPLICATION = "application"


# --- Sent frame metadata (lightweight — not the actual bytes) ---


@dataclass(frozen=True, slots=True)
class SentCryptoFrame:
    """CRYPTO frame that was sent — offset and length for retransmission."""

    offset: int
    length: int


@dataclass(frozen=True, slots=True)
class SentStreamFrame:
    """STREAM frame that was sent — stream ID, offset, length, FIN."""

    stream_id: int
    offset: int
    length: int
    fin: bool


@dataclass(frozen=True, slots=True)
class SentAckFrame:
    """ACK frame that was sent. Not retransmittable (RFC 9002)."""


@dataclass(frozen=True, slots=True)
class SentHandshakeDoneFrame:
    """HANDSHAKE_DONE frame that was sent."""


@dataclass(frozen=True, slots=True)
class SentNewConnectionIdFrame:
    """NEW_CONNECTION_ID frame that was sent."""

    sequence: int


@dataclass(frozen=True, slots=True)
class SentPingFrame:
    """PING frame that was sent."""


SentFrame = (
    SentCryptoFrame
    | SentStreamFrame
    | SentAckFrame
    | SentHandshakeDoneFrame
    | SentNewConnectionIdFrame
    | SentPingFrame
)


@dataclass(frozen=True, slots=True)
class SentPacket:
    """Metadata for a sent QUIC packet — used for loss detection and RTT."""

    packet_number: int
    sent_time: float
    sent_bytes: int
    ack_eliciting: bool
    in_flight: bool
    frames: tuple[SentFrame, ...]
