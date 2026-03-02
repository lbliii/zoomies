"""RFC 9000 variable-length integer encoding (Section 16)."""

from zoomies.encoding.buffer import VARINT_MAX, Buffer

# Length prefixes: 2 bits -> bytes
# 00: 1 byte (6 bits)
# 01: 2 bytes (14 bits)
# 10: 4 bytes (30 bits)
# 11: 8 bytes (62 bits)


def pull_varint(buf: Buffer) -> int:
    """Read variable-length integer from buffer."""
    first = buf.pull_uint8()
    prefix = first >> 6
    if prefix == 0:
        return first & 0x3F
    if prefix == 1:
        return ((first & 0x3F) << 8) | buf.pull_uint8()
    if prefix == 2:
        return (
            ((first & 0x3F) << 24)
            | (buf.pull_uint8() << 16)
            | (buf.pull_uint8() << 8)
            | buf.pull_uint8()
        )
    # prefix == 3
    return (
        ((first & 0x3F) << 56)
        | (buf.pull_uint8() << 48)
        | (buf.pull_uint8() << 40)
        | (buf.pull_uint8() << 32)
        | (buf.pull_uint8() << 24)
        | (buf.pull_uint8() << 16)
        | (buf.pull_uint8() << 8)
        | buf.pull_uint8()
    )


def push_varint(buf: Buffer, value: int) -> None:
    """Write variable-length integer to buffer."""
    if value < 0 or value > VARINT_MAX:
        raise ValueError(f"Varint must be 0-{VARINT_MAX}, got {value}")
    if value <= 0x3F:
        buf.push_uint8(value)
    elif value <= 0x3FFF:
        buf.push_uint8(0x40 | (value >> 8))
        buf.push_uint8(value & 0xFF)
    elif value <= 0x3FFFFFFF:
        buf.push_uint8(0x80 | (value >> 24))
        buf.push_uint8((value >> 16) & 0xFF)
        buf.push_uint8((value >> 8) & 0xFF)
        buf.push_uint8(value & 0xFF)
    else:
        buf.push_uint8(0xC0 | (value >> 56))
        buf.push_uint8((value >> 48) & 0xFF)
        buf.push_uint8((value >> 40) & 0xFF)
        buf.push_uint8((value >> 32) & 0xFF)
        buf.push_uint8((value >> 24) & 0xFF)
        buf.push_uint8((value >> 16) & 0xFF)
        buf.push_uint8((value >> 8) & 0xFF)
        buf.push_uint8(value & 0xFF)
