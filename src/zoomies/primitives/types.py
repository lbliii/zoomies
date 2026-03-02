"""Protocol primitive types — RFC 9000 identifiers and enums."""

from dataclasses import dataclass
from enum import IntEnum, StrEnum

# RFC 9000 2.1: Stream identifiers are 62-bit integers.
# Bit 0: initiator (client=0, server=1)
# Bit 1: direction (bidirectional=0, unidirectional=1)
STREAM_ID_MAX = 2**62 - 1

# RFC 9000 12.3: Packet numbers are 62-bit.
PACKET_NUMBER_MAX = 2**62 - 1

# RFC 9000 5.1: Connection IDs are 0-20 bytes.
CONNECTION_ID_MIN_LEN = 0
CONNECTION_ID_MAX_LEN = 20


@dataclass(frozen=True, slots=True)
class ConnectionId:
    """0-20 bytes. Canonical key for a connection (RFC 9000 5.1)."""

    value: bytes

    def __post_init__(self) -> None:
        if len(self.value) > CONNECTION_ID_MAX_LEN:
            raise ValueError(
                f"ConnectionId must be 0-{CONNECTION_ID_MAX_LEN} bytes, got {len(self.value)}"
            )


@dataclass(frozen=True, slots=True)
class StreamId:
    """62-bit. Bit 0 = initiator, bit 1 = direction (RFC 9000 2.1)."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= STREAM_ID_MAX:
            raise ValueError(f"StreamId must be 0-{STREAM_ID_MAX}, got {self.value}")


@dataclass(frozen=True, slots=True)
class PacketNumber:
    """62-bit. Monotonically increasing per packet number space."""

    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= PACKET_NUMBER_MAX:
            raise ValueError(f"PacketNumber must be 0-{PACKET_NUMBER_MAX}, got {self.value}")


class FrameType(IntEnum):
    """QUIC frame types (RFC 9000 12-19)."""

    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    ACK_ECN = 0x03
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    NEW_TOKEN = 0x07
    STREAM = 0x08
    MAX_DATA = 0x10
    MAX_STREAM_DATA = 0x11
    MAX_STREAMS = 0x12
    DATA_BLOCKED = 0x14
    STREAM_DATA_BLOCKED = 0x15
    STREAMS_BLOCKED = 0x16
    NEW_CONNECTION_ID = 0x18
    RETIRE_CONNECTION_ID = 0x19
    PATH_CHALLENGE = 0x1A
    PATH_RESPONSE = 0x1B
    CONNECTION_CLOSE = 0x1C
    HANDSHAKE_DONE = 0x1E


class PacketType(IntEnum):
    """QUIC packet types (RFC 9000 17.2)."""

    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3
    ONE_RTT = 4  # short header


class PacketNumberSpace(StrEnum):
    """Packet number spaces (RFC 9000 12.3)."""

    INITIAL = "initial"
    HANDSHAKE = "handshake"
    APPLICATION = "application"
