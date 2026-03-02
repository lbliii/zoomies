"""Packet header parse, transport params, ACK (RFC 9000, aioquic patterns)."""

from zoomies.encoding import Buffer
from zoomies.frames import AckFrame, push_ack_frame
from zoomies.packet import (
    LongHeader,
    QuicTransportParameters,
    ShortHeader,
    decode_packet_number,
    pull_quic_header,
    pull_quic_transport_parameters,
    push_quic_transport_parameters,
)
from zoomies.packet.header import PACKET_TYPE_INITIAL, QUIC_VERSION_1


class TestDecodePacketNumber:
    def test_rfc_sample(self) -> None:
        # RFC 9000 Appendix A sample
        assert decode_packet_number(0, 8, 0) == 0
        assert decode_packet_number(1, 8, 0) == 1
        assert decode_packet_number(0xFF, 8, 0) == 255
        assert decode_packet_number(0, 8, 256) == 256

    def test_small_window(self) -> None:
        assert decode_packet_number(50, 16, 100) == 50


class TestPullQuicHeader:
    def test_initial_header(self) -> None:
        # Build minimal Initial: 1 byte type, 4 version, 1+8 dcid, 1+8 scid,
        # varint token_len=0, varint payload_len
        buf = Buffer()
        buf.push_uint8(0xC0)  # long, fixed, Initial
        buf.push_uint32(QUIC_VERSION_1)
        buf.push_uint8(8)
        buf.push_bytes(b"destcid8")
        buf.push_uint8(8)
        buf.push_bytes(b"srccid08")
        buf.push_uint_var(0)  # token length 0
        buf.push_uint_var(100)  # payload length
        buf.push_bytes(bytes(100))  # dummy payload
        buf.seek(0)
        header = pull_quic_header(buf)
        assert isinstance(header, LongHeader)
        assert header.version == QUIC_VERSION_1
        assert header.packet_type == PACKET_TYPE_INITIAL
        assert header.destination_cid == b"destcid8"
        assert header.source_cid == b"srccid08"
        assert header.payload_length == 100

    def test_short_header(self) -> None:
        # Short: 0100 0xxx (fixed, spin, reserved, kp, pn_len=01 -> 2 bytes)
        buf = Buffer()
        buf.push_uint8(0x41)  # short, fixed, pn_len=2
        buf.push_bytes(b"12345678")  # 8-byte dcid
        buf.push_uint16(42)  # packet number
        buf.seek(0)
        header = pull_quic_header(buf, host_cid_length=8)
        assert isinstance(header, ShortHeader)
        assert header.destination_cid == b"12345678"
        assert header.packet_number == 42
        assert header.packet_number_size == 2


class TestTransportParams:
    def test_roundtrip(self) -> None:
        params = QuicTransportParameters(
            original_destination_connection_id=b"\x01\x02\x03",
            max_idle_timeout=30_000,
            initial_max_data=100_000,
        )
        buf = Buffer()
        push_quic_transport_parameters(buf, params)
        buf.seek(0)
        parsed = pull_quic_transport_parameters(buf)
        assert parsed.original_destination_connection_id == b"\x01\x02\x03"
        assert parsed.max_idle_timeout == 30_000
        assert parsed.initial_max_data == 100_000


class TestAckInPacket:
    """ACK frame in packet context."""

    def test_push_ack_roundtrip(self) -> None:
        frame = AckFrame(ranges=(range(10, 15),), delay=0)
        buf = Buffer()
        push_ack_frame(buf, frame)
        buf.seek(0)
        from zoomies.frames import pull_ack_frame

        parsed = pull_ack_frame(buf)
        assert parsed.ranges == frame.ranges
