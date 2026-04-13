"""Tests for stateful QpackEncoder/QpackDecoder with dynamic table."""

from zoomies.events import StreamDataReceived
from zoomies.h3.qpack import Header, QpackDecoder, QpackEncoder


class TestQpackEncoderDecoder:
    def test_static_only_roundtrip(self) -> None:
        """Static-table headers work with stateful encoder/decoder."""
        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)

        headers = [
            Header(name=":method", value="GET"),
            Header(name=":path", value="/"),
        ]
        encoded = enc.encode(headers)

        # Feed encoder stream instructions to decoder
        dec.feed_encoder_stream(enc.encoder_stream_data())

        decoded = dec.decode(encoded)
        assert len(decoded) == 2
        assert decoded[0].name == ":method"
        assert decoded[0].value == "GET"
        assert decoded[1].name == ":path"
        assert decoded[1].value == "/"

    def test_dynamic_table_compression(self) -> None:
        """Repeated custom headers get smaller on second encoding."""
        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)

        headers = [
            Header(name="x-request-id", value="abc-123"),
            Header(name="authorization", value="Bearer tok"),
        ]

        # First encoding -- inserts into dynamic table
        encoded1 = enc.encode(headers)
        dec.feed_encoder_stream(enc.encoder_stream_data())
        decoded1 = dec.decode(encoded1)
        assert len(decoded1) == 2
        assert decoded1[0].name == "x-request-id"
        assert decoded1[0].value == "abc-123"

        # Second encoding -- should use dynamic table references
        encoded2 = enc.encode(headers)
        dec.feed_encoder_stream(enc.encoder_stream_data())
        decoded2 = dec.decode(encoded2)
        assert len(decoded2) == 2
        assert decoded2[0].name == "x-request-id"
        assert decoded2[0].value == "abc-123"

        # Second encoding should be smaller (dynamic refs vs literals)
        assert len(encoded2) < len(encoded1)

    def test_static_name_ref(self) -> None:
        """Header with static name but non-static value uses name ref."""
        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)

        headers = [
            Header(name=":status", value="201"),  # name in static, value not
        ]
        encoded = enc.encode(headers)
        dec.feed_encoder_stream(enc.encoder_stream_data())
        decoded = dec.decode(encoded)
        assert decoded[0].name == ":status"
        assert decoded[0].value == "201"

    def test_zero_capacity_no_dynamic(self) -> None:
        """Zero capacity means no dynamic table entries."""
        enc = QpackEncoder(max_table_capacity=0)
        dec = QpackDecoder(max_table_capacity=0)

        headers = [Header(name="x-custom", value="val")]
        encoded1 = enc.encode(headers)
        encoded2 = enc.encode(headers)

        # No compression gain -- both encodings same size
        assert len(encoded1) == len(encoded2)

        decoded = dec.decode(encoded1)
        assert decoded[0].name == "x-custom"
        assert decoded[0].value == "val"

    def test_encode_from_bytes(self) -> None:
        """encode_from_bytes works with dynamic table."""
        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)

        headers = [(b":status", b"200"), (b"content-type", b"text/plain")]
        encoded = enc.encode_from_bytes(headers)
        dec.feed_encoder_stream(enc.encoder_stream_data())
        decoded = dec.decode(encoded)
        assert decoded[0].name == ":status"
        assert decoded[0].value == "200"
        assert decoded[1].name == "content-type"
        assert decoded[1].value == "text/plain"

    def test_mixed_static_and_custom(self) -> None:
        """Mix of static and custom headers round-trips correctly."""
        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)

        headers = [
            Header(name=":method", value="POST"),
            Header(name=":path", value="/api/v1"),
            Header(name=":scheme", value="https"),
            Header(name="x-trace-id", value="trace-001"),
            Header(name="content-type", value="application/json"),
        ]
        encoded = enc.encode(headers)
        dec.feed_encoder_stream(enc.encoder_stream_data())
        decoded = dec.decode(encoded)
        assert len(decoded) == 5
        for orig, dec_h in zip(headers, decoded, strict=True):
            assert orig.name == dec_h.name
            assert orig.value == dec_h.value

    def test_many_repeated_requests(self) -> None:
        """Compression improves over many repeated requests."""
        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)
        dec = QpackDecoder(max_table_capacity=4096)
        dec.set_capacity(4096)

        headers = [
            Header(name=":method", value="GET"),
            Header(name=":path", value="/api/users"),
            Header(name="authorization", value="Bearer token123"),
            Header(name="x-request-id", value="req-001"),
        ]

        sizes: list[int] = []
        for _ in range(5):
            encoded = enc.encode(headers)
            dec.feed_encoder_stream(enc.encoder_stream_data())
            decoded = dec.decode(encoded)
            assert len(decoded) == 4
            for orig, dec_h in zip(headers, decoded, strict=True):
                assert orig.name == dec_h.name
                assert orig.value == dec_h.value
            sizes.append(len(encoded))

        # First encoding is largest; subsequent ones are smaller
        assert sizes[1] < sizes[0]
        # All subsequent encodings are the same size (fully cached)
        assert sizes[1] == sizes[2] == sizes[3] == sizes[4]


class TestH3ConnectionDynamic:
    def test_dynamic_table_via_h3(self) -> None:
        """H3Connection with dynamic table enabled compresses headers."""
        from zoomies.h3.connection import H3Connection

        sent: list[tuple[int, bytes, bool]] = []

        class MockSender:
            def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
                sent.append((stream_id, data, end_stream))

        conn = H3Connection(sender=MockSender(), is_client=True, qpack_max_table_capacity=4096)

        headers = [
            (b":status", b"200"),
            (b"x-custom", b"value1"),
        ]

        conn.send_headers(stream_id=0, headers=headers)
        first_send = [s for s in sent if s[0] == 0]
        assert len(first_send) == 1

        sent.clear()
        conn.send_headers(stream_id=4, headers=headers)
        second_send = [s for s in sent if s[0] == 4]
        assert len(second_send) == 1

        # Second frame should be smaller (dynamic table refs)
        assert len(second_send[0][1]) < len(first_send[0][1])

    def test_backward_compat_no_dynamic(self) -> None:
        """H3Connection without dynamic table works as before."""
        from zoomies.h3.connection import H3Connection

        sent: list[tuple[int, bytes, bool]] = []

        class MockSender:
            def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
                sent.append((stream_id, data, end_stream))

        conn = H3Connection(sender=MockSender())
        conn.send_headers(
            stream_id=4,
            headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
        )
        assert len(sent) == 1
        assert sent[0][0] == 4

    def test_decode_with_dynamic_table(self) -> None:
        """H3Connection decodes header blocks from stateful encoder."""
        from zoomies.events import H3HeadersReceived
        from zoomies.h3.connection import H3_FRAME_HEADERS, H3Connection, _encode_frame

        enc = QpackEncoder(max_table_capacity=4096)
        enc.set_capacity(4096)

        headers = [
            Header(name=":method", value="GET"),
            Header(name="x-custom", value="test"),
        ]
        payload = enc.encode(headers)
        frame = _encode_frame(H3_FRAME_HEADERS, payload)

        conn = H3Connection(is_client=True, qpack_max_table_capacity=4096)
        # Feed encoder instructions to the connection's decoder
        conn.feed_encoder_stream(enc.encoder_stream_data())

        event = StreamDataReceived(stream_id=0, data=frame, end_stream=True)
        events = conn.handle_event(event)
        assert len(events) == 1
        assert isinstance(events[0], H3HeadersReceived)
        assert events[0].headers[0] == (b":method", b"GET")
        assert events[0].headers[1] == (b"x-custom", b"test")
