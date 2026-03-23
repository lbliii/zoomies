"""Shared HKDF helpers for TLS 1.3 and QUIC packet protection (RFC 8446, RFC 9001)."""

import struct

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def hkdf_label(label: bytes, context: bytes, length: int) -> bytes:
    """TLS 1.3 HKDF label format (RFC 8446 7.1)."""
    full_label = b"tls13 " + label
    return (
        struct.pack("!HB", length, len(full_label))
        + full_label
        + struct.pack("!B", len(context))
        + context
    )


def hkdf_extract(
    algorithm: type[hashes.HashAlgorithm],
    salt: bytes,
    key_material: bytes,
) -> bytes:
    """HKDF-Extract (RFC 5869)."""
    h = hmac.HMAC(salt, algorithm())
    h.update(key_material)
    return h.finalize()


def hkdf_expand_label(
    algorithm: type[hashes.HashAlgorithm],
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    """HKDF-Expand-Label (RFC 8446 7.1)."""
    return HKDFExpand(
        algorithm=algorithm(),
        length=length,
        info=hkdf_label(label, context, length),
    ).derive(secret)
