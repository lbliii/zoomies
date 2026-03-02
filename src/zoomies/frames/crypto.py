"""CRYPTO frame (RFC 9000 19.6) — TLS handshake data."""

from dataclasses import dataclass

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint, push_varint

CRYPTO_FRAME_TYPE = 0x06


@dataclass(frozen=True, slots=True)
class CryptoFrame:
    """CRYPTO frame — offset and crypto data for TLS handshake."""

    offset: int
    data: bytes


def pull_crypto_frame(buf: Buffer) -> CryptoFrame:
    """Parse CRYPTO frame. RFC 9000 19.6: Type, Offset, Length, Data."""
    frame_type = pull_varint(buf)
    if frame_type != CRYPTO_FRAME_TYPE:
        raise ValueError(f"Not a CRYPTO frame (type {frame_type})")
    offset = pull_varint(buf)
    length = pull_varint(buf)
    data = buf.pull_bytes(length)
    return CryptoFrame(offset=offset, data=data)


def push_crypto_frame(buf: Buffer, frame: CryptoFrame) -> None:
    """Serialize CRYPTO frame to buffer."""
    push_varint(buf, CRYPTO_FRAME_TYPE)
    push_varint(buf, frame.offset)
    push_varint(buf, len(frame.data))
    buf.push_bytes(frame.data)
