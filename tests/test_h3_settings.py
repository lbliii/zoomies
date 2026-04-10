"""Tests for H3 SETTINGS frame and QPACK capacity negotiation."""

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint
from zoomies.h3.connection import (
    H3_STREAM_TYPE_CONTROL,
    SETTINGS_QPACK_BLOCKED_STREAMS,
    SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    H3Connection,
    decode_settings,
    encode_settings,
)


class TestSettingsCodec:
    def test_roundtrip_empty(self) -> None:
        data = encode_settings({})
        assert decode_settings(data) == {}

    def test_roundtrip_single(self) -> None:
        settings = {SETTINGS_QPACK_MAX_TABLE_CAPACITY: 4096}
        data = encode_settings(settings)
        assert decode_settings(data) == settings

    def test_roundtrip_multiple(self) -> None:
        settings = {
            SETTINGS_QPACK_MAX_TABLE_CAPACITY: 4096,
            SETTINGS_QPACK_BLOCKED_STREAMS: 100,
        }
        data = encode_settings(settings)
        assert decode_settings(data) == settings


class TestH3ConnectionSettings:
    def test_local_settings_default(self) -> None:
        """No QPACK settings when capacity is 0."""
        conn = H3Connection()
        assert conn.local_settings() == {}

    def test_local_settings_with_capacity(self) -> None:
        conn = H3Connection(qpack_max_table_capacity=4096)
        settings = conn.local_settings()
        assert settings[SETTINGS_QPACK_MAX_TABLE_CAPACITY] == 4096

    def test_local_settings_with_blocked_streams(self) -> None:
        conn = H3Connection(
            qpack_max_table_capacity=4096,
            qpack_blocked_streams=100,
        )
        settings = conn.local_settings()
        assert settings[SETTINGS_QPACK_MAX_TABLE_CAPACITY] == 4096
        assert settings[SETTINGS_QPACK_BLOCKED_STREAMS] == 100

    def test_settings_data_includes_stream_type(self) -> None:
        """settings_data() returns control stream type + SETTINGS frame."""
        conn = H3Connection(qpack_max_table_capacity=4096)
        data = conn.settings_data()
        assert data is not None
        buf = Buffer(data=data)
        stream_type = pull_varint(buf)
        assert stream_type == H3_STREAM_TYPE_CONTROL
        # Next is SETTINGS frame: type (0x04) + length + payload
        frame_type = pull_varint(buf)
        assert frame_type == 0x04

    def test_settings_data_only_sent_once(self) -> None:
        conn = H3Connection(qpack_max_table_capacity=4096)
        first = conn.settings_data()
        second = conn.settings_data()
        assert first is not None
        assert second is None

    def test_settings_data_empty_when_no_capacity(self) -> None:
        """Even with no QPACK capacity, settings_data returns valid frame."""
        conn = H3Connection()
        data = conn.settings_data()
        assert data is not None
        buf = Buffer(data=data)
        stream_type = pull_varint(buf)
        assert stream_type == H3_STREAM_TYPE_CONTROL


class TestPeerSettingsNegotiation:
    def test_apply_peer_settings_reduces_capacity(self) -> None:
        """Encoder capacity becomes min(local, peer)."""
        conn = H3Connection(qpack_max_table_capacity=4096)
        assert conn.encoder is not None
        conn.apply_peer_settings({SETTINGS_QPACK_MAX_TABLE_CAPACITY: 2048})
        assert conn.encoder.table.capacity == 2048

    def test_apply_peer_settings_zero_disables(self) -> None:
        """Peer advertising 0 disables the dynamic table."""
        conn = H3Connection(qpack_max_table_capacity=4096)
        assert conn.encoder is not None
        conn.apply_peer_settings({SETTINGS_QPACK_MAX_TABLE_CAPACITY: 0})
        assert conn.encoder.table.capacity == 0

    def test_apply_peer_settings_larger_capped(self) -> None:
        """Peer advertising more than local max gets capped."""
        conn = H3Connection(qpack_max_table_capacity=4096)
        assert conn.encoder is not None
        conn.apply_peer_settings(
            {SETTINGS_QPACK_MAX_TABLE_CAPACITY: 8192}
        )
        assert conn.encoder.table.capacity == 4096

    def test_apply_peer_settings_no_qpack_key(self) -> None:
        """Missing QPACK key means peer doesn't support dynamic table."""
        conn = H3Connection(qpack_max_table_capacity=4096)
        assert conn.encoder is not None
        conn.apply_peer_settings({})
        # Encoder capacity stays at 0 since peer didn't advertise
        assert conn.encoder.table.capacity == 0

    def test_peer_settings_stored(self) -> None:
        conn = H3Connection(qpack_max_table_capacity=4096)
        assert conn.peer_settings is None
        settings = {SETTINGS_QPACK_MAX_TABLE_CAPACITY: 2048}
        conn.apply_peer_settings(settings)
        assert conn.peer_settings == settings

    def test_settings_frame_parsed_from_stream(self) -> None:
        """SETTINGS frame received on a stream is parsed and applied."""
        from zoomies.h3.connection import H3_FRAME_SETTINGS, _encode_frame

        conn = H3Connection(qpack_max_table_capacity=4096)
        settings = {SETTINGS_QPACK_MAX_TABLE_CAPACITY: 2048}
        payload = encode_settings(settings)
        frame = _encode_frame(H3_FRAME_SETTINGS, payload)

        events = conn.stream_data_received(
            stream_id=2, data=frame, end_stream=False
        )
        # SETTINGS doesn't produce H3 events
        assert len(events) == 0
        # But peer settings should be applied
        assert conn.peer_settings == settings
        assert conn.encoder is not None
        assert conn.encoder.table.capacity == 2048
