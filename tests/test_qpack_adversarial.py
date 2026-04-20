"""Adversarial tests for QPACK encoder/decoder."""

import pytest

from zoomies.encoding import Buffer
from zoomies.h3.dynamic_table import DynamicTable
from zoomies.h3.qpack import QpackDecoder, QpackEncoder
from zoomies.h3.qpack_instructions import (
    encode_set_capacity,
)


class TestDynamicTableAdversarial:
    def test_zero_capacity_insert(self) -> None:
        """Insert on zero-capacity table is a no-op, not a crash."""
        table = DynamicTable(capacity=0)
        table.insert("key", "value")
        assert len(table) == 0
        assert table.size == 0

    def test_oversized_entry(self) -> None:
        """Entry larger than capacity clears table gracefully."""
        table = DynamicTable(capacity=64)
        table.insert("a", "b")
        table.insert("x" * 100, "y" * 100)
        assert len(table) == 0
        assert table.size == 0

    def test_get_negative_index(self) -> None:
        table = DynamicTable(capacity=4096)
        table.insert("a", "b")
        with pytest.raises(IndexError):
            table.get(-1)

    def test_get_beyond_length(self) -> None:
        table = DynamicTable(capacity=4096)
        with pytest.raises(IndexError):
            table.get(0)

    def test_shrink_to_zero(self) -> None:
        table = DynamicTable(capacity=4096)
        for i in range(10):
            table.insert(f"key{i}", f"val{i}")
        table.set_capacity(0)
        assert len(table) == 0
        assert table.size == 0


class TestDecoderAdversarial:
    def test_encoder_stream_capacity_exceeds_max(self) -> None:
        """Decoder handles set_capacity beyond its max gracefully."""
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)
        buf = Buffer()
        encode_set_capacity(buf, 99999)
        # Decoder should process it -- RFC says decoder must accept
        # any capacity the encoder sets (encoder is responsible for
        # respecting the negotiated limit)
        dec.feed_encoder_stream(buf.data)
        assert dec.table.capacity == 99999

    def test_encoder_stream_ref_beyond_table(self) -> None:
        """Referencing non-existent dynamic entry raises IndexError."""
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)
        # Build an instruction that references dynamic index 5 (empty table)
        buf = Buffer()
        # Insert With Name Reference (dynamic), index 5
        buf.push_uint8(0x80 | 5)  # 1[0]xxxxx = dynamic, index 5
        # Value: empty string
        buf.push_uint8(0x00)  # length 0

        with pytest.raises(IndexError):
            dec.feed_encoder_stream(buf.data)

    def test_malformed_varint(self) -> None:
        """Truncated varint in encoder stream raises ValueError."""
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)
        # 0x3F = Set Capacity with value needing continuation, but no more bytes
        with pytest.raises((ValueError, IndexError)):
            dec.feed_encoder_stream(bytes([0x3F]))

    def test_ric_exceeds_full_range(self) -> None:
        """Encoded RIC exceeding full range is rejected."""
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)
        # max_entries = 4096 // 32 = 128, full_range = 256
        # encoded_ric = 257 > 256 → should fail
        buf = Buffer()
        from zoomies.h3.qpack_instructions import _push_prefixed_int

        _push_prefixed_int(buf, 0x00, 8, 257)
        buf.push_uint8(0)  # Delta Base = 0
        with pytest.raises(ValueError, match=r"full_range=\d+"):
            dec.decode(buf.data)

    def test_empty_header_block(self) -> None:
        """Header block with just RIC=0 and Delta Base=0 returns empty list."""
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)
        buf = Buffer()
        buf.push_uint8(0)  # RIC = 0
        buf.push_uint8(0)  # Delta Base = 0
        result = dec.decode(buf.data)
        assert result == []


class TestEncoderAdversarial:
    def test_zero_capacity_no_instructions(self) -> None:
        """Zero-capacity encoder emits no encoder stream data."""
        from zoomies.h3.qpack import Header

        enc = QpackEncoder(max_table_capacity=0)
        headers = [Header(name="x-custom", value="val")]
        enc.encode(headers)
        assert enc.encoder_stream_data() == b""

    def test_encoder_handles_empty_headers(self) -> None:

        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        result = enc.encode([])
        # Should be just RIC + Delta Base (2 bytes)
        assert len(result) == 2

    def test_rapid_capacity_changes(self) -> None:
        """Multiple rapid capacity changes don't corrupt state."""
        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        enc.set_capacity(100)
        enc.set_capacity(0)
        enc.set_capacity(2048)
        assert enc.table.capacity == 2048
