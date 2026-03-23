"""QUIC Retry packet integrity (RFC 9001 5.8)."""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zoomies.primitives.types import QUIC_VERSION_1

# RFC 9001 5.8: Retry packet integrity (QUIC v1)
RETRY_AEAD_KEY_V1 = bytes.fromhex("be0c690b9f66575a1d766b54e368c84e")
RETRY_AEAD_NONCE_V1 = bytes.fromhex("461599d35d632bf2239825bb")
RETRY_INTEGRITY_TAG_SIZE = 16


def get_retry_integrity_tag(
    packet_without_tag: bytes,
    original_destination_cid: bytes,
    version: int = QUIC_VERSION_1,
) -> bytes:
    """Compute Retry integrity tag (RFC 9001 5.8)."""
    # Retry pseudo-packet: ODCID length (1) + ODCID + packet
    pseudo = bytes([len(original_destination_cid)]) + original_destination_cid + packet_without_tag
    aead = AESGCM(RETRY_AEAD_KEY_V1)
    ciphertext = aead.encrypt(RETRY_AEAD_NONCE_V1, pseudo, b"")
    return ciphertext[-RETRY_INTEGRITY_TAG_SIZE:]


def encode_quic_retry(
    version: int,
    source_cid: bytes,
    destination_cid: bytes,
    original_destination_cid: bytes,
    retry_token: bytes,
) -> bytes:
    """Build Retry packet (RFC 9000 17.2.4)."""
    # First byte: 1 (long) | 1 (fixed) | 11 (Retry) | 00 (unused)
    first_byte = 0xC0 | (3 << 4)
    packet_without_tag = (
        bytes([first_byte])
        + version.to_bytes(4, "big")
        + bytes([len(destination_cid)])
        + destination_cid
        + bytes([len(source_cid)])
        + source_cid
        + retry_token
    )
    tag = get_retry_integrity_tag(packet_without_tag, original_destination_cid, version)
    return packet_without_tag + tag
