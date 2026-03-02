"""QUIC packet builder — headers, ACK frames (RFC 9000)."""

from zoomies.encoding import Buffer
from zoomies.packet.header import (
    PACKET_FIXED_BIT,
    PACKET_LONG_HEADER,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
)

QUIC_VERSION_1 = 0x0000_0001


def _encode_long_type(packet_type: int) -> int:
    """Encode long packet type into first byte bits."""
    return (packet_type & 0x03) << 4


def push_quic_header(
    buf: Buffer,
    packet_type: int,
    version: int,
    destination_cid: bytes,
    source_cid: bytes,
    token: bytes = b"",
    payload_length: int = 0,
) -> None:
    """Push long header (Initial, 0-RTT, Handshake)."""
    first = PACKET_LONG_HEADER | PACKET_FIXED_BIT | _encode_long_type(packet_type)
    buf.push_uint8(first)
    buf.push_uint32(version)
    buf.push_uint8(len(destination_cid))
    buf.push_bytes(destination_cid)
    buf.push_uint8(len(source_cid))
    buf.push_bytes(source_cid)
    if packet_type == PACKET_TYPE_INITIAL:
        buf.push_uint_var(len(token))
        buf.push_bytes(token)
    buf.push_uint_var(payload_length)


def push_initial_packet_header(
    buf: Buffer,
    destination_cid: bytes,
    source_cid: bytes,
    token: bytes,
    payload_length: int,
) -> None:
    """Convenience: push Initial packet long header."""
    push_quic_header(
        buf,
        PACKET_TYPE_INITIAL,
        QUIC_VERSION_1,
        destination_cid,
        source_cid,
        token=token,
        payload_length=payload_length,
    )


def push_handshake_packet_header(
    buf: Buffer,
    destination_cid: bytes,
    source_cid: bytes,
    payload_length: int,
) -> None:
    """Convenience: push Handshake packet long header."""
    push_quic_header(
        buf,
        PACKET_TYPE_HANDSHAKE,
        QUIC_VERSION_1,
        destination_cid,
        source_cid,
        payload_length=payload_length,
    )


def push_short_header(
    buf: Buffer,
    destination_cid: bytes,
    packet_number: int,
    pn_len: int = 4,
) -> None:
    """Push Short header (1-RTT). RFC 9000 17.3.

    pn_len: 1, 2, or 4 bytes for packet number.
    """
    if pn_len not in (1, 2, 4):
        raise ValueError("pn_len must be 1, 2, or 4")
    first = PACKET_FIXED_BIT | (pn_len - 1)
    buf.push_uint8(first)
    buf.push_bytes(destination_cid)
    buf.push_bytes(packet_number.to_bytes(pn_len, "big"))
