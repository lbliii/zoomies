"""QUIC packet headers — long and short (RFC 9000 17.2, 17.3)."""

from dataclasses import dataclass

from zoomies.encoding import Buffer
from zoomies.encoding.buffer import BufferReadError
from zoomies.primitives.types import CONNECTION_ID_MAX_LEN, QUIC_VERSION_1  # noqa: F401

# RFC 9000 17.2: Long header has high bit set
PACKET_LONG_HEADER = 0x80
PACKET_FIXED_BIT = 0x40

# RFC 9000 17.2: Long packet types (version 1)
# 00=Initial, 01=0-RTT, 10=Handshake, 11=Retry
PACKET_TYPE_INITIAL = 0
PACKET_TYPE_ZERO_RTT = 1
PACKET_TYPE_HANDSHAKE = 2
PACKET_TYPE_RETRY = 3
QUIC_VERSION_NEGOTIATION = 0x0000_0000
RETRY_INTEGRITY_TAG_SIZE = 16


@dataclass(frozen=True, slots=True)
class LongHeader:
    """Long header — Initial, 0-RTT, Handshake, Retry."""

    version: int
    packet_type: int  # 0-3
    destination_cid: bytes
    source_cid: bytes
    token: bytes
    integrity_tag: bytes
    payload_length: int
    packet_number: int | None  # None for Retry


@dataclass(frozen=True, slots=True)
class ShortHeader:
    """Short header — 1-RTT (RFC 9000 17.3)."""

    destination_cid: bytes
    packet_number: int
    packet_number_size: int  # 1, 2, or 4


def _is_long_header(first_byte: int) -> bool:
    return bool(first_byte & PACKET_LONG_HEADER)


def pull_destination_cid_for_routing(
    data: bytes,
    known_cids: tuple[bytes, ...] = (),
) -> bytes | None:
    """Extract destination CID from datagram for connection routing.

    For long headers: parses and returns destination_cid.
    For short headers: returns matching cid from known_cids if packet starts with it.
    Returns None if parsing fails or no match.
    """
    if len(data) < 7:
        return None
    try:
        buf = Buffer(data=data)
        first_byte = buf.pull_uint8()
        if _is_long_header(first_byte):
            buf.pull_uint32()
            dest_cid_len = buf.pull_uint8()
            if dest_cid_len > CONNECTION_ID_MAX_LEN:
                return None
            return buf.pull_bytes(dest_cid_len)
        if first_byte & PACKET_FIXED_BIT and known_cids:
            for cid in known_cids:
                if cid and len(data) >= 1 + len(cid) and data[1 : 1 + len(cid)] == cid:
                    return cid
    except ValueError, BufferReadError:
        pass
    return None


def decode_packet_number(truncated: int, num_bits: int, expected: int) -> int:
    """Recover packet number from truncated encoding (RFC 9000 Appendix A)."""
    window = 1 << num_bits
    half_window = window // 2
    candidate = (expected & ~(window - 1)) | truncated
    if candidate <= expected - half_window and candidate < (1 << 62) - window:
        return candidate + window
    if candidate > expected + half_window and candidate >= window:
        return candidate - window
    return candidate


def pull_quic_header(buf: Buffer, host_cid_length: int | None = None) -> LongHeader | ShortHeader:
    """Parse QUIC header. Returns LongHeader or ShortHeader."""
    total_len = len(buf.data)

    first_byte = buf.pull_uint8()
    if _is_long_header(first_byte):
        version = buf.pull_uint32()

        dest_cid_len = buf.pull_uint8()
        if dest_cid_len > CONNECTION_ID_MAX_LEN:
            raise ValueError(f"Destination CID too long ({dest_cid_len} bytes)")
        dest_cid = buf.pull_bytes(dest_cid_len)

        src_cid_len = buf.pull_uint8()
        if src_cid_len > CONNECTION_ID_MAX_LEN:
            raise ValueError(f"Source CID too long ({src_cid_len} bytes)")
        src_cid = buf.pull_bytes(src_cid_len)

        if version == QUIC_VERSION_NEGOTIATION:
            raise ValueError("Version Negotiation packet — use pull_version_negotiation")

        if not (first_byte & PACKET_FIXED_BIT):
            raise ValueError("Packet fixed bit is zero")

        packet_type = (first_byte & 0x30) >> 4

        token = b""
        integrity_tag = b""
        payload_length = 0
        packet_number: int | None = None

        if packet_type == PACKET_TYPE_INITIAL:
            token_len = buf.pull_uint_var()
            token = buf.pull_bytes(token_len)
            payload_length = buf.pull_uint_var()
        elif packet_type in (PACKET_TYPE_ZERO_RTT, PACKET_TYPE_HANDSHAKE):
            payload_length = buf.pull_uint_var()
        else:
            # RETRY
            remaining = total_len - buf.tell() - RETRY_INTEGRITY_TAG_SIZE
            if remaining < 0:
                raise BufferReadError("Retry packet truncated")
            token = buf.pull_bytes(remaining)
            integrity_tag = buf.pull_bytes(RETRY_INTEGRITY_TAG_SIZE)
            payload_length = 0

        packet_end = buf.tell() + payload_length
        if packet_end > total_len:
            raise ValueError("Packet payload truncated")

        # For non-Retry, packet number is in payload (opaque until decrypt)
        return LongHeader(
            version=version,
            packet_type=packet_type,
            destination_cid=dest_cid,
            source_cid=src_cid,
            token=token,
            integrity_tag=integrity_tag,
            payload_length=payload_length,
            packet_number=packet_number,
        )

    # Short header
    if not (first_byte & PACKET_FIXED_BIT):
        raise ValueError("Packet fixed bit is zero")
    if host_cid_length is None:
        raise ValueError("host_cid_length required for short header")
    dest_cid = buf.pull_bytes(host_cid_length)
    # RFC 9000 17.3: 00=1 byte, 01=2 bytes, 10=4 bytes, 11=4 bytes
    pn_len_map = (1, 2, 4, 4)
    pn_len = pn_len_map[first_byte & 0x03]
    pn_bytes = buf.pull_bytes(pn_len)
    pn = int.from_bytes(pn_bytes, "big")
    return ShortHeader(
        destination_cid=dest_cid,
        packet_number=pn,
        packet_number_size=pn_len,
    )
