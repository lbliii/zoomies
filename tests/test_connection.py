"""QUIC connection — handshake, stream, close."""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.encoding import Buffer
from zoomies.events import DatagramReceived, HandshakeComplete
from zoomies.packet.builder import push_initial_packet_header

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")


def _make_initial_packet(
    dest_cid: bytes = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08",
    src_cid: bytes = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5",
    payload: bytes = b"\x00" * 50,
) -> bytes:
    """Build minimal Initial packet (header + payload, unencrypted for test)."""
    buf = Buffer()
    push_initial_packet_header(
        buf,
        destination_cid=dest_cid,
        source_cid=src_cid,
        token=b"",
        payload_length=len(payload),
    )
    return buf.data + payload


def test_connection_datagram_received() -> None:
    """datagram_received returns events."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    pkt = _make_initial_packet()
    events = conn.datagram_received(pkt, ("127.0.0.1", 443))
    assert any(isinstance(e, DatagramReceived) for e in events)
    assert any(isinstance(e, HandshakeComplete) for e in events)


def test_connection_send_datagrams() -> None:
    """send_datagrams returns queued datagrams after receiving Initial."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    pkt = _make_initial_packet()
    conn.datagram_received(pkt, ("127.0.0.1", 443))
    datagrams = conn.send_datagrams()
    assert len(datagrams) >= 1
    assert len(datagrams[0]) > 18
    # Second call returns empty (already sent)
    assert conn.send_datagrams() == []


def test_connection_handshake_complete() -> None:
    """HandshakeComplete emitted when Initial processed."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    pkt = _make_initial_packet()
    events = conn.datagram_received(pkt, ("127.0.0.1", 443))
    assert any(isinstance(e, HandshakeComplete) for e in events)


def test_connection_send_stream_data_queues() -> None:
    """send_stream_data queues data (H3StreamSender protocol)."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=True)
    conn.send_stream_data(stream_id=4, data=b"world", end_stream=False)
    # Queue is internal; verify send_datagrams still works (returns Initial if any)
    # and that no exception is raised
    datagrams = conn.send_datagrams()
    # Before receiving Initial, send_datagrams returns [] (no Initial response)
    # After receiving, it would return Initial packets. Here we just verify
    # send_stream_data doesn't break anything.
    assert isinstance(datagrams, list)


def test_h3_connection_wired_to_quic_send_stream_data() -> None:
    """H3Connection(quic_conn) send_headers flows to QuicConnection.send_stream_data."""
    from zoomies.h3 import H3Connection

    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    quic = QuicConnection(config)
    h3 = H3Connection(sender=quic)
    h3.send_headers(
        stream_id=0,
        headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
        end_stream=False,
    )
    h3.send_data(stream_id=0, data=b"ok", end_stream=True)
    # QuicConnection queued the stream data; verify queue has entries
    assert len(quic._stream_send_queue) == 2
