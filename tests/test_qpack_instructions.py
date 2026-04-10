"""Tests for QPACK encoder/decoder stream instructions (RFC 9204 SS4.3-4.4)."""

from zoomies.encoding import Buffer
from zoomies.h3.qpack_instructions import (
    decode_all_decoder_instructions,
    decode_all_encoder_instructions,
    decode_decoder_instruction,
    decode_encoder_instruction,
    encode_duplicate,
    encode_insert_count_increment,
    encode_insert_literal,
    encode_insert_name_ref,
    encode_section_ack,
    encode_set_capacity,
    encode_stream_cancellation,
)

# ---------------------------------------------------------------------------
# Encoder instructions round-trip
# ---------------------------------------------------------------------------


class TestSetCapacity:
    def test_small(self) -> None:
        buf = Buffer()
        encode_set_capacity(buf, 100)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("set_capacity", {"capacity": 100})

    def test_zero(self) -> None:
        buf = Buffer()
        encode_set_capacity(buf, 0)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("set_capacity", {"capacity": 0})

    def test_large(self) -> None:
        buf = Buffer()
        encode_set_capacity(buf, 65536)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("set_capacity", {"capacity": 65536})


class TestInsertNameRef:
    def test_static_ref(self) -> None:
        buf = Buffer()
        encode_insert_name_ref(buf, is_static=True, name_index=18, value="hello")
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("insert_name_ref", {
            "is_static": True,
            "name_index": 18,
            "value": "hello",
        })

    def test_dynamic_ref(self) -> None:
        buf = Buffer()
        encode_insert_name_ref(buf, is_static=False, name_index=3, value="world")
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("insert_name_ref", {
            "is_static": False,
            "name_index": 3,
            "value": "world",
        })

    def test_empty_value(self) -> None:
        buf = Buffer()
        encode_insert_name_ref(buf, is_static=True, name_index=0, value="")
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result[1]["value"] == ""


class TestInsertLiteral:
    def test_basic(self) -> None:
        buf = Buffer()
        encode_insert_literal(buf, "x-custom", "foobar")
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("insert_literal", {"name": "x-custom", "value": "foobar"})

    def test_empty_value(self) -> None:
        buf = Buffer()
        encode_insert_literal(buf, "x-key", "")
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("insert_literal", {"name": "x-key", "value": ""})


class TestDuplicate:
    def test_basic(self) -> None:
        buf = Buffer()
        encode_duplicate(buf, 5)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("duplicate", {"index": 5})

    def test_zero(self) -> None:
        buf = Buffer()
        encode_duplicate(buf, 0)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("duplicate", {"index": 0})


class TestMultipleEncoderInstructions:
    def test_decode_all(self) -> None:
        buf = Buffer()
        encode_set_capacity(buf, 4096)
        encode_insert_literal(buf, "server", "zoomies")
        encode_insert_name_ref(buf, is_static=True, name_index=18, value="/api")
        instructions = decode_all_encoder_instructions(buf.data)
        assert len(instructions) == 3
        assert instructions[0][0] == "set_capacity"
        assert instructions[1][0] == "insert_literal"
        assert instructions[2][0] == "insert_name_ref"


# ---------------------------------------------------------------------------
# Decoder instructions round-trip
# ---------------------------------------------------------------------------


class TestSectionAck:
    def test_basic(self) -> None:
        buf = Buffer()
        encode_section_ack(buf, 4)
        result = decode_decoder_instruction(Buffer(data=buf.data))
        assert result == ("section_ack", {"stream_id": 4})

    def test_large_stream_id(self) -> None:
        buf = Buffer()
        encode_section_ack(buf, 1000)
        result = decode_decoder_instruction(Buffer(data=buf.data))
        assert result == ("section_ack", {"stream_id": 1000})


class TestStreamCancellation:
    def test_basic(self) -> None:
        buf = Buffer()
        encode_stream_cancellation(buf, 8)
        result = decode_decoder_instruction(Buffer(data=buf.data))
        assert result == ("stream_cancellation", {"stream_id": 8})


class TestInsertCountIncrement:
    def test_basic(self) -> None:
        buf = Buffer()
        encode_insert_count_increment(buf, 3)
        result = decode_decoder_instruction(Buffer(data=buf.data))
        assert result == ("insert_count_increment", {"increment": 3})


class TestMultipleDecoderInstructions:
    def test_decode_all(self) -> None:
        buf = Buffer()
        encode_section_ack(buf, 4)
        encode_stream_cancellation(buf, 8)
        encode_insert_count_increment(buf, 1)
        instructions = decode_all_decoder_instructions(buf.data)
        assert len(instructions) == 3
        assert instructions[0][0] == "section_ack"
        assert instructions[1][0] == "stream_cancellation"
        assert instructions[2][0] == "insert_count_increment"


# ---------------------------------------------------------------------------
# Prefixed integer edge cases
# ---------------------------------------------------------------------------


class TestPrefixedIntEdgeCases:
    def test_max_prefix_boundary(self) -> None:
        """Value exactly at max prefix (2^N - 1) triggers multi-byte encoding."""
        buf = Buffer()
        # 5-bit prefix: max = 31
        encode_set_capacity(buf, 31)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("set_capacity", {"capacity": 31})

    def test_above_max_prefix(self) -> None:
        buf = Buffer()
        encode_set_capacity(buf, 32)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("set_capacity", {"capacity": 32})

    def test_large_value(self) -> None:
        buf = Buffer()
        encode_set_capacity(buf, 100000)
        result = decode_encoder_instruction(Buffer(data=buf.data))
        assert result == ("set_capacity", {"capacity": 100000})
