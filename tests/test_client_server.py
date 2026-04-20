"""Client-server loopback integration tests.

Two QuicConnection instances (client + server) exchange datagrams in the same process.
"""

import os

import pytest

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import (
    ConnectionClosed,
    DecryptionFailed,
    HandshakeComplete,
    StreamDataReceived,
)

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)


def _make_client_server() -> tuple[QuicConnection, QuicConnection]:
    """Create a client and server connection pair."""
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    server = QuicConnection(server_config)
    client = QuicConnection(client_config)
    return client, server


def _transfer(sender: QuicConnection, receiver: QuicConnection) -> list:
    """Shuttle all datagrams from sender to receiver; return all events."""
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, ADDR))
    return events


def _handshake(client: QuicConnection, server: QuicConnection) -> None:
    """Complete full handshake between client and server."""
    # Client sends Initial (ClientHello)
    client.connect()

    # Server receives Initial, produces response (Initial + Handshake + 1-RTT)
    _transfer(client, server)

    # Client receives server response — may need multiple rounds
    # Server sends Initial+Handshake+1-RTT (ServerHello, EE, Cert, Finished, HANDSHAKE_DONE)
    _transfer(server, client)

    # Client sends: Handshake (client Finished) + ACKs
    _transfer(client, server)

    # Server may send ACKs back
    _transfer(server, client)


# --- Handshake tests ---


def test_client_connect_produces_initial() -> None:
    """Client.connect() queues an Initial packet."""
    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()
    datagrams = client.send_datagrams()
    assert len(datagrams) >= 1
    # Initial packet should be at least 1200 bytes (RFC 9000 §14.1)
    assert len(datagrams[0]) >= 1200


def test_server_rejects_connect() -> None:
    """Server cannot call connect()."""
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    server = QuicConnection(server_config)
    with pytest.raises(RuntimeError, match="is_client=True"):
        server.connect()


def test_handshake_completes() -> None:
    """Client and server complete QUIC handshake."""
    client, server = _make_client_server()
    client.connect()

    # Client → Server: Initial (ClientHello)
    server_events = _transfer(client, server)
    # Server should have received the datagram
    assert any(not isinstance(e, type(None)) for e in server_events)

    # Server → Client: Initial + Handshake + 1-RTT
    client_events = _transfer(server, client)

    # Client should have handshake complete (HANDSHAKE_DONE received)
    handshake_events = [e for e in client_events if isinstance(e, HandshakeComplete)]
    if not handshake_events:
        # May need another round
        _transfer(client, server)
        client_events = _transfer(server, client)
        handshake_events = [e for e in client_events if isinstance(e, HandshakeComplete)]

    assert len(handshake_events) >= 1


def test_bidirectional_stream_data() -> None:
    """Client and server exchange stream data after handshake."""
    client, server = _make_client_server()
    _handshake(client, server)

    # Client sends data to server
    client.send_stream_data(0, b"hello from client", end_stream=True)
    server_events = _transfer(client, server)
    stream_events = [e for e in server_events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) >= 1
    assert stream_events[0].data == b"hello from client"
    assert stream_events[0].end_stream is True

    # Server sends data to client
    server.send_stream_data(0, b"hello from server", end_stream=True)
    client_events = _transfer(server, client)
    stream_events = [e for e in client_events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) >= 1
    assert stream_events[0].data == b"hello from server"
    assert stream_events[0].end_stream is True


def test_client_close() -> None:
    """Client can close connection after handshake."""
    client, server = _make_client_server()
    _handshake(client, server)

    client.close(error_code=0, reason="done")
    server_events = _transfer(client, server)
    close_events = [e for e in server_events if isinstance(e, ConnectionClosed)]
    assert len(close_events) >= 1


def test_server_close() -> None:
    """Server can close connection after handshake."""
    client, server = _make_client_server()
    _handshake(client, server)

    server.close(error_code=0, reason="done")
    client_events = _transfer(server, client)
    close_events = [e for e in client_events if isinstance(e, ConnectionClosed)]
    assert len(close_events) >= 1


# --- Sprint 3: Edge cases ---


def test_multiple_streams() -> None:
    """Client and server exchange data on multiple independent streams."""
    client, server = _make_client_server()
    _handshake(client, server)

    # Client sends on streams 0 and 4 (client-initiated bidirectional)
    client.send_stream_data(0, b"stream-zero", end_stream=True)
    client.send_stream_data(4, b"stream-four", end_stream=True)
    server_events = _transfer(client, server)
    stream_events = [e for e in server_events if isinstance(e, StreamDataReceived)]
    received = {e.stream_id: e.data for e in stream_events}
    assert received[0] == b"stream-zero"
    assert received[4] == b"stream-four"


def test_large_stream_data() -> None:
    """Data larger than a single MTU arrives intact."""
    client, server = _make_client_server()
    _handshake(client, server)

    payload = os.urandom(10_000)
    client.send_stream_data(0, payload, end_stream=True)

    # May need multiple transfer rounds for all packets + ACKs
    received = b""
    for _ in range(5):
        server_events = _transfer(client, server)
        for e in server_events:
            if isinstance(e, StreamDataReceived) and e.stream_id == 0:
                received += e.data
        _transfer(server, client)  # ACKs back to unblock congestion window
    assert received == payload


def test_close_with_error_code() -> None:
    """Error code and reason propagate in ConnectionClosed event."""
    client, server = _make_client_server()
    _handshake(client, server)

    client.close(error_code=0x0A, reason="protocol violation")
    server_events = _transfer(client, server)
    close_events = [e for e in server_events if isinstance(e, ConnectionClosed)]
    assert len(close_events) >= 1
    assert close_events[0].error_code == 0x0A
    assert close_events[0].reason == "protocol violation"


def _transfer_timed(sender: QuicConnection, receiver: QuicConnection, now: float) -> list:
    """Shuttle datagrams with timestamps."""
    events = []
    for dg in sender.send_datagrams(now=now):
        events.extend(receiver.datagram_received(dg, ADDR, now=now))
    return events


def _handshake_timed(client: QuicConnection, server: QuicConnection, now: float = 1.0) -> None:
    """Complete handshake with proper timestamps for timer tests."""
    client.connect()
    _transfer_timed(client, server, now)
    _transfer_timed(server, client, now + 0.01)
    _transfer_timed(client, server, now + 0.02)
    _transfer_timed(server, client, now + 0.03)


def test_idle_timeout_client() -> None:
    """Client idle timeout fires and closes the connection."""
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY, idle_timeout=5.0)
    client_config = QuicConfiguration(is_client=True, verify_mode=False, idle_timeout=5.0)
    server = QuicConnection(server_config)
    client = QuicConnection(client_config)

    _handshake_timed(client, server, now=1.0)

    # Advance time well past idle timeout
    events = client.handle_timer(now=100.0)
    close_events = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(close_events) >= 1


def test_idle_timeout_server() -> None:
    """Server idle timeout fires and closes the connection."""
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY, idle_timeout=5.0)
    client_config = QuicConfiguration(is_client=True, verify_mode=False, idle_timeout=5.0)
    server = QuicConnection(server_config)
    client = QuicConnection(client_config)

    _handshake_timed(client, server, now=1.0)

    events = server.handle_timer(now=100.0)
    close_events = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(close_events) >= 1


def test_client_receives_corrupted_packet() -> None:
    """Corrupted bytes after handshake produce DecryptionFailed, not a crash."""
    client, server = _make_client_server()
    _handshake(client, server)

    # Build a garbage short header packet with the right CID prefix
    garbage = bytes([0x40]) + client._our_cid + os.urandom(50)
    events = client.datagram_received(garbage, ADDR)
    decrypt_events = [e for e in events if isinstance(e, DecryptionFailed)]
    assert len(decrypt_events) >= 1


def test_server_receives_corrupted_packet() -> None:
    """Corrupted bytes to server produce DecryptionFailed, not a crash."""
    client, server = _make_client_server()
    _handshake(client, server)

    garbage = bytes([0x40]) + server._our_cid + os.urandom(50)
    events = server.datagram_received(garbage, ADDR)
    decrypt_events = [e for e in events if isinstance(e, DecryptionFailed)]
    assert len(decrypt_events) >= 1


def test_pto_sends_probe() -> None:
    """PTO fires when packets are unacknowledged, sending a PING probe."""
    client, server = _make_client_server()
    _handshake_timed(client, server, now=1.0)

    # Client sends stream data — drop it (don't deliver)
    client.send_stream_data(0, b"will be lost", end_stream=True)
    _dropped = client.send_datagrams(now=2.0)
    assert len(_dropped) >= 1

    # PTO should fire — get the deadline and advance past it
    timer = client.get_timer()
    assert timer is not None
    fire_time = max(timer, 2.0) + 1.0  # safely past any deadline
    client.handle_timer(now=fire_time)

    # Client should queue a PING probe
    probe_dgs = client.send_datagrams(now=fire_time)
    assert len(probe_dgs) >= 1
