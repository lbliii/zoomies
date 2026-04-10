"""QPACK encoder/decoder stream instructions (RFC 9204 SS4.3-4.4)."""

from __future__ import annotations

from zoomies.encoding import Buffer

# ---------------------------------------------------------------------------
# Encoder instructions (RFC 9204 §4.3) — sent on encoder stream
# ---------------------------------------------------------------------------


def encode_set_capacity(buf: Buffer, capacity: int) -> None:
    """Encode Set Dynamic Table Capacity instruction (§4.3.1).

    Format: 0b001xxxxx + varint capacity (5-bit prefix).
    """
    _push_prefixed_int(buf, 0x20, 5, capacity)


def encode_insert_name_ref(buf: Buffer, *, is_static: bool, name_index: int, value: str) -> None:
    """Encode Insert With Name Reference instruction (§4.3.2).

    Static ref:  0b1[1]xxxxxx + varint index (6-bit prefix) + value
    Dynamic ref: 0b1[0]xxxxxx + varint index (6-bit prefix) + value
    """
    prefix_byte = 0xC0 if is_static else 0x80
    _push_prefixed_int(buf, prefix_byte, 6, name_index)
    _push_string(buf, value, prefix_bits=7)


def encode_insert_literal(buf: Buffer, name: str, value: str) -> None:
    """Encode Insert With Literal Name instruction (§4.3.3).

    Format: 0b01xxxxxx + name (5-bit prefix) + value (7-bit prefix).
    """
    _push_prefixed_int(buf, 0x40, 5, len(name.encode("utf-8")))
    buf.push_bytes(name.encode("utf-8"))
    _push_string(buf, value, prefix_bits=7)


def encode_duplicate(buf: Buffer, index: int) -> None:
    """Encode Duplicate instruction (§4.3.4).

    Format: 0b000xxxxx + varint index (5-bit prefix).
    """
    _push_prefixed_int(buf, 0x00, 5, index)


# ---------------------------------------------------------------------------
# Decoder instructions (RFC 9204 §4.4) — sent on decoder stream
# ---------------------------------------------------------------------------


def encode_section_ack(buf: Buffer, stream_id: int) -> None:
    """Encode Section Acknowledgment (§4.4.1).

    Format: 0b1xxxxxxx + varint stream_id (7-bit prefix).
    """
    _push_prefixed_int(buf, 0x80, 7, stream_id)


def encode_stream_cancellation(buf: Buffer, stream_id: int) -> None:
    """Encode Stream Cancellation (§4.4.2).

    Format: 0b01xxxxxx + varint stream_id (6-bit prefix).
    """
    _push_prefixed_int(buf, 0x40, 6, stream_id)


def encode_insert_count_increment(buf: Buffer, increment: int) -> None:
    """Encode Insert Count Increment (§4.4.3).

    Format: 0b00xxxxxx + varint increment (6-bit prefix).
    """
    _push_prefixed_int(buf, 0x00, 6, increment)


# ---------------------------------------------------------------------------
# Decoding — encoder stream instructions
# ---------------------------------------------------------------------------


def decode_encoder_instruction(buf: Buffer) -> tuple[str, dict]:
    """Decode one encoder stream instruction.

    Returns: (instruction_type, fields) where instruction_type is one of:
      "set_capacity", "insert_name_ref", "insert_literal", "duplicate"
    """
    first = buf.pull_uint8()
    buf.seek(buf.tell() - 1)

    if first & 0x80:
        # Insert With Name Reference (§4.3.2)
        byte = buf.pull_uint8()
        is_static = bool(byte & 0x40)
        name_index = _pull_prefixed_int(buf, byte, 6)
        value = _pull_string(buf, prefix_bits=7)
        return (
            "insert_name_ref",
            {
                "is_static": is_static,
                "name_index": name_index,
                "value": value,
            },
        )
    elif first & 0x40:
        # Insert With Literal Name (§4.3.3)
        byte = buf.pull_uint8()
        name_len = _pull_prefixed_int(buf, byte, 5)
        name = buf.pull_bytes(name_len).decode("utf-8")
        value = _pull_string(buf, prefix_bits=7)
        return ("insert_literal", {"name": name, "value": value})
    elif first & 0x20:
        # Set Dynamic Table Capacity (§4.3.1)
        byte = buf.pull_uint8()
        capacity = _pull_prefixed_int(buf, byte, 5)
        return ("set_capacity", {"capacity": capacity})
    else:
        # Duplicate (§4.3.4)
        byte = buf.pull_uint8()
        index = _pull_prefixed_int(buf, byte, 5)
        return ("duplicate", {"index": index})


def decode_all_encoder_instructions(data: bytes) -> list[tuple[str, dict]]:
    """Decode all encoder stream instructions from bytes."""
    buf = Buffer(data=data)
    instructions: list[tuple[str, dict]] = []
    while not buf.eof():
        instructions.append(decode_encoder_instruction(buf))
    return instructions


# ---------------------------------------------------------------------------
# Decoding — decoder stream instructions
# ---------------------------------------------------------------------------


def decode_decoder_instruction(buf: Buffer) -> tuple[str, dict]:
    """Decode one decoder stream instruction.

    Returns: (instruction_type, fields) where instruction_type is one of:
      "section_ack", "stream_cancellation", "insert_count_increment"
    """
    first = buf.pull_uint8()
    buf.seek(buf.tell() - 1)

    if first & 0x80:
        # Section Acknowledgment (§4.4.1)
        byte = buf.pull_uint8()
        stream_id = _pull_prefixed_int(buf, byte, 7)
        return ("section_ack", {"stream_id": stream_id})
    elif first & 0x40:
        # Stream Cancellation (§4.4.2)
        byte = buf.pull_uint8()
        stream_id = _pull_prefixed_int(buf, byte, 6)
        return ("stream_cancellation", {"stream_id": stream_id})
    else:
        # Insert Count Increment (§4.4.3)
        byte = buf.pull_uint8()
        increment = _pull_prefixed_int(buf, byte, 6)
        return ("insert_count_increment", {"increment": increment})


def decode_all_decoder_instructions(data: bytes) -> list[tuple[str, dict]]:
    """Decode all decoder stream instructions from bytes."""
    buf = Buffer(data=data)
    instructions: list[tuple[str, dict]] = []
    while not buf.eof():
        instructions.append(decode_decoder_instruction(buf))
    return instructions


# ---------------------------------------------------------------------------
# Prefixed integer encoding (RFC 7541 §5.1, used by QPACK)
# ---------------------------------------------------------------------------


def _push_prefixed_int(buf: Buffer, prefix_byte: int, prefix_bits: int, value: int) -> None:
    """Encode an integer with a prefix (RFC 7541 §5.1)."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        buf.push_uint8(prefix_byte | value)
    else:
        buf.push_uint8(prefix_byte | max_prefix)
        value -= max_prefix
        while value >= 128:
            buf.push_uint8((value & 0x7F) | 0x80)
            value >>= 7
        buf.push_uint8(value)


def _pull_prefixed_int(buf: Buffer, first_byte: int, prefix_bits: int) -> int:
    """Decode a prefixed integer (RFC 7541 §5.1).

    first_byte has already been consumed from buf.
    """
    max_prefix = (1 << prefix_bits) - 1
    value = first_byte & max_prefix
    if value < max_prefix:
        return value
    shift = 0
    while True:
        b = buf.pull_uint8()
        value += (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return value


def _push_string(buf: Buffer, value: str, *, prefix_bits: int) -> None:
    """Encode a string with length prefix (no Huffman for now)."""
    encoded = value.encode("utf-8")
    _push_prefixed_int(buf, 0x00, prefix_bits, len(encoded))
    buf.push_bytes(encoded)


def _pull_string(buf: Buffer, *, prefix_bits: int) -> str:
    """Decode a string with length prefix (no Huffman)."""
    first = buf.pull_uint8()
    # Bit 7 (of the string length byte) = Huffman flag; we don't support Huffman yet
    huffman = bool(first & (1 << prefix_bits))
    length = _pull_prefixed_int(buf, first, prefix_bits)
    data = buf.pull_bytes(length)
    if huffman:
        raise ValueError("Huffman-encoded strings not supported")
    return data.decode("utf-8")
