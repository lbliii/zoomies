"""Retry integration tests — end-to-end Retry with HTTP/3.

Sprint 4 capstone: proves the full Retry flow from Initial through HTTP/3
request/response. Exercises server Retry send, client Retry handling,
token validation, ODCID tracking, and post-handshake HTTP/3 over a
single loopback connection pair.
"""

import pytest

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection, RetryReceived
from zoomies.core.connection import ConnectionState
from zoomies.events import (
    H3DataReceived,
    H3HeadersReceived,
    HandshakeComplete,
    StreamDataReceived,
)
from zoomies.h3 import H3Connection

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)


class SimpleRetryTokenHandler:
    """Minimal Retry token handler for integration tests.

    Token = len(ODCID) || ODCID || addr_string. No encryption, no expiry.
    """

    def generate_token(self, original_dcid: bytes, client_addr: tuple[str, int]) -> bytes:
        addr_bytes = f"{client_addr[0]}:{client_addr[1]}".encode()
        return bytes([len(original_dcid)]) + original_dcid + addr_bytes

    def validate_token(self, token: bytes, client_addr: tuple[str, int]) -> bytes | None:
        if len(token) < 1:
            return None
        odcid_len = token[0]
        if len(token) < 1 + odcid_len:
            return None
        odcid = token[1 : 1 + odcid_len]
        addr_bytes = token[1 + odcid_len :]
        expected_addr = f"{client_addr[0]}:{client_addr[1]}".encode()
        if addr_bytes != expected_addr:
            return None
        return odcid


def _transfer(sender: QuicConnection, receiver: QuicConnection) -> list:
    """Shuttle all datagrams from sender to receiver; return all events."""
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, ADDR))
    return events


def _collect_h3_events(
    quic_events: list, h3: H3Connection
) -> list[H3HeadersReceived | H3DataReceived]:
    """Feed QUIC events through H3 and collect H3 events."""
    h3_events: list[H3HeadersReceived | H3DataReceived] = []
    for evt in quic_events:
        h3_events.extend(h3.handle_event(evt))
    return h3_events


def _retry_handshake(
    client: QuicConnection, server: QuicConnection
) -> list:
    """Complete handshake with Retry. Returns all client events from the flow."""
    all_client_events: list = []

    # 1. Client → Server: Initial (no token)
    client.connect()
    _transfer(client, server)

    # 2. Server → Client: Retry
    client_events = _transfer(server, client)
    all_client_events.extend(client_events)

    # 3. Client → Server: Initial (with token)
    _transfer(client, server)

    # 4. Server → Client: Initial + Handshake + 1-RTT
    client_events = _transfer(server, client)
    all_client_events.extend(client_events)

    # 5. Client → Server: Handshake (Finished) + ACKs
    _transfer(client, server)

    # 6. Server → Client: final ACKs
    client_events = _transfer(server, client)
    all_client_events.extend(client_events)

    return all_client_events


# --- Integration tests ---


@pytest.mark.integration
def test_retry_h3_get_request_response() -> None:
    """Full Retry → handshake → HTTP/3 GET / → 200 + body."""
    handler = SimpleRetryTokenHandler()
    server_quic = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, retry_token_handler=handler)
    )
    client_quic = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False)
    )
    h3_client = H3Connection(sender=client_quic)
    h3_server = H3Connection(sender=server_quic)

    # Retry + handshake
    client_events = _retry_handshake(client_quic, server_quic)

    # Verify Retry was received
    assert any(isinstance(e, RetryReceived) for e in client_events)

    # Verify handshake completed
    assert any(isinstance(e, HandshakeComplete) for e in client_events)
    assert server_quic._state == ConnectionState.ONE_RTT
    assert client_quic._state == ConnectionState.ONE_RTT
    assert server_quic._address_validated is True
    assert server_quic._original_destination_cid is not None

    # Client sends GET /
    stream_id = 0
    h3_client.send_headers(
        stream_id=stream_id,
        headers=[
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
        ],
        end_stream=True,
    )

    # Transfer client → server
    server_quic_events = _transfer(client_quic, server_quic)
    h3_events = _collect_h3_events(server_quic_events, h3_server)

    # Server receives request headers
    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    assert len(header_events) == 1
    assert dict(header_events[0].headers)[b":method"] == b"GET"
    assert dict(header_events[0].headers)[b":path"] == b"/"
    assert header_events[0].end_stream is True

    # Server sends 200 response
    h3_server.send_headers(
        stream_id=stream_id,
        headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
        end_stream=False,
    )
    h3_server.send_data(stream_id=stream_id, data=b"Hello after Retry!", end_stream=True)

    # Transfer server → client
    client_quic_events = _transfer(server_quic, client_quic)
    h3_events = _collect_h3_events(client_quic_events, h3_client)

    # Client receives response
    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    data_events = [e for e in h3_events if isinstance(e, H3DataReceived)]
    assert len(header_events) == 1
    assert dict(header_events[0].headers)[b":status"] == b"200"
    assert len(data_events) == 1
    assert data_events[0].data == b"Hello after Retry!"
    assert data_events[0].end_stream is True


@pytest.mark.integration
def test_retry_h3_post_with_body() -> None:
    """Retry → handshake → HTTP/3 POST with body → server receives it."""
    handler = SimpleRetryTokenHandler()
    server_quic = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, retry_token_handler=handler)
    )
    client_quic = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False)
    )
    h3_client = H3Connection(sender=client_quic)
    h3_server = H3Connection(sender=server_quic)

    _retry_handshake(client_quic, server_quic)

    # Client sends POST /submit
    stream_id = 0
    h3_client.send_headers(
        stream_id=stream_id,
        headers=[
            (b":method", b"POST"),
            (b":path", b"/submit"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b"content-type", b"application/json"),
        ],
        end_stream=False,
    )
    h3_client.send_data(stream_id=stream_id, data=b'{"retry": true}', end_stream=True)

    server_quic_events = _transfer(client_quic, server_quic)
    h3_events = _collect_h3_events(server_quic_events, h3_server)

    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    data_events = [e for e in h3_events if isinstance(e, H3DataReceived)]
    assert len(header_events) == 1
    assert dict(header_events[0].headers)[b":method"] == b"POST"
    assert len(data_events) == 1
    assert data_events[0].data == b'{"retry": true}'


@pytest.mark.integration
def test_retry_bidirectional_stream_after_handshake() -> None:
    """Retry → handshake → bidirectional QUIC stream data works."""
    handler = SimpleRetryTokenHandler()
    server_quic = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, retry_token_handler=handler)
    )
    client_quic = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False)
    )

    _retry_handshake(client_quic, server_quic)

    # Client → Server
    client_quic.send_stream_data(0, b"ping", end_stream=True)
    server_events = _transfer(client_quic, server_quic)
    stream_events = [e for e in server_events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) == 1
    assert stream_events[0].data == b"ping"
    assert stream_events[0].end_stream is True

    # Server → Client
    server_quic.send_stream_data(0, b"pong", end_stream=True)
    client_events = _transfer(server_quic, client_quic)
    stream_events = [e for e in client_events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) == 1
    assert stream_events[0].data == b"pong"
    assert stream_events[0].end_stream is True


@pytest.mark.integration
def test_retry_multiple_h3_requests() -> None:
    """Retry → handshake → multiple HTTP/3 requests on different streams."""
    handler = SimpleRetryTokenHandler()
    server_quic = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, retry_token_handler=handler)
    )
    client_quic = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False)
    )
    h3_client = H3Connection(sender=client_quic)
    h3_server = H3Connection(sender=server_quic)

    _retry_handshake(client_quic, server_quic)

    # Two concurrent GET requests
    h3_client.send_headers(
        stream_id=0,
        headers=[
            (b":method", b"GET"),
            (b":path", b"/one"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
        ],
        end_stream=True,
    )
    h3_client.send_headers(
        stream_id=4,
        headers=[
            (b":method", b"GET"),
            (b":path", b"/two"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
        ],
        end_stream=True,
    )

    server_quic_events = _transfer(client_quic, server_quic)
    h3_events = _collect_h3_events(server_quic_events, h3_server)

    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    paths = {dict(e.headers)[b":path"] for e in header_events}
    assert b"/one" in paths
    assert b"/two" in paths


@pytest.mark.integration
def test_retry_odcid_tracked_correctly() -> None:
    """Server tracks the original destination CID through Retry flow."""
    handler = SimpleRetryTokenHandler()
    server_quic = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, retry_token_handler=handler)
    )
    client_quic = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False)
    )

    # Trigger connect so the client generates its initial destination CID,
    # then capture it before the Retry flow overwrites it.
    client_quic.connect()
    original_peer_cid = client_quic._peer_cid
    assert len(original_peer_cid) > 0

    # Run the Retry handshake manually (connect already called)
    _transfer(client_quic, server_quic)       # Initial (no token)
    _transfer(server_quic, client_quic)       # Retry
    _transfer(client_quic, server_quic)       # Initial (with token)
    _transfer(server_quic, client_quic)       # Handshake
    _transfer(client_quic, server_quic)       # Client Finished
    _transfer(server_quic, client_quic)       # ACKs

    # Server must have stored the ODCID from the first Initial
    assert server_quic._original_destination_cid is not None
    assert server_quic._original_destination_cid == original_peer_cid
