"""Retry packet integrity (RFC 9001 5.8)."""

from zoomies.packet.retry import encode_quic_retry, get_retry_integrity_tag

QUIC_VERSION_1 = 0x0000_0001


def test_retry_integrity_roundtrip() -> None:
    """Encode Retry, verify tag is 16 bytes and packet is valid."""
    src = b"src_cid_8"  # 9 bytes
    dest = b"destcid8"  # 8 bytes
    odcid = b"odcid___8"  # 8 bytes
    token = b"retry_token_data"
    packet = encode_quic_retry(QUIC_VERSION_1, src, dest, odcid, token)
    # Packet = 1 + 4 + 1 + 8 + 1 + 9 + token + 16
    assert len(packet) == 1 + 4 + 1 + len(dest) + 1 + len(src) + len(token) + 16
    tag = packet[-16:]
    packet_without_tag = packet[:-16]
    computed = get_retry_integrity_tag(packet_without_tag, odcid)
    assert computed == tag


def test_retry_structure() -> None:
    """Retry packet has correct structure."""
    packet = encode_quic_retry(
        QUIC_VERSION_1,
        source_cid=b"\x01" * 8,
        destination_cid=b"\x02" * 8,
        original_destination_cid=b"\x03" * 8,
        retry_token=b"",
    )
    # First byte: 0xC0 | 0x30 = 0xF0 (long, fixed, Retry)
    assert packet[0] == 0xF0
    assert packet[1:5] == QUIC_VERSION_1.to_bytes(4, "big")
    assert packet[5] == 8  # dest cid len
    assert packet[6:14] == b"\x02" * 8
    assert packet[14] == 8  # src cid len
    assert packet[15:23] == b"\x01" * 8
    assert len(packet) == 23 + 16  # token empty + tag
