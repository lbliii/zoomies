"""HTTP/3 client-server loopback — full request/response over QUIC."""

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import H3DataReceived, H3HeadersReceived
from zoomies.h3 import H3Connection

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)


def _make_pair() -> tuple[QuicConnection, QuicConnection, H3Connection, H3Connection]:
    """Create a QUIC client+server pair with H3 on top."""
    server_quic = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client_quic = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))
    h3_client = H3Connection(sender=client_quic)
    h3_server = H3Connection(sender=server_quic)
    return client_quic, server_quic, h3_client, h3_server


def _transfer(sender: QuicConnection, receiver: QuicConnection) -> list:
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, ADDR))
    return events


def _handshake(client: QuicConnection, server: QuicConnection) -> None:
    client.connect()
    _transfer(client, server)
    _transfer(server, client)
    _transfer(client, server)
    _transfer(server, client)


def _collect_h3_events(
    quic_events: list, h3: H3Connection
) -> list[H3HeadersReceived | H3DataReceived]:
    """Feed QUIC events through H3 and collect H3 events."""
    h3_events: list[H3HeadersReceived | H3DataReceived] = []
    for evt in quic_events:
        h3_events.extend(h3.handle_event(evt))
    return h3_events


# --- Tests ---


def test_h3_get_request_response() -> None:
    """Client sends GET / → server receives headers → server responds 200 + body."""
    client_quic, server_quic, h3_client, h3_server = _make_pair()
    _handshake(client_quic, server_quic)

    # Client sends GET request
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

    # Server should receive the request headers
    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    assert len(header_events) == 1
    req = header_events[0]
    assert req.stream_id == stream_id
    headers_dict = dict(req.headers)
    assert headers_dict[b":method"] == b"GET"
    assert headers_dict[b":path"] == b"/"
    assert req.end_stream is True

    # Server sends response
    h3_server.send_headers(
        stream_id=stream_id,
        headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
        end_stream=False,
    )
    h3_server.send_data(stream_id=stream_id, data=b"Hello, World!", end_stream=True)

    # Transfer server → client
    client_quic_events = _transfer(server_quic, client_quic)
    h3_events = _collect_h3_events(client_quic_events, h3_client)

    # Client should receive response headers + data
    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    data_events = [e for e in h3_events if isinstance(e, H3DataReceived)]
    assert len(header_events) == 1
    resp = header_events[0]
    assert dict(resp.headers)[b":status"] == b"200"
    assert len(data_events) == 1
    assert data_events[0].data == b"Hello, World!"
    assert data_events[0].end_stream is True


def test_h3_post_request_with_body() -> None:
    """Client sends POST with body → server receives headers + data."""
    client_quic, server_quic, h3_client, h3_server = _make_pair()
    _handshake(client_quic, server_quic)

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
    h3_client.send_data(
        stream_id=stream_id, data=b'{"key": "value"}', end_stream=True
    )

    server_quic_events = _transfer(client_quic, server_quic)
    h3_events = _collect_h3_events(server_quic_events, h3_server)

    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    data_events = [e for e in h3_events if isinstance(e, H3DataReceived)]
    assert len(header_events) == 1
    assert dict(header_events[0].headers)[b":method"] == b"POST"
    assert len(data_events) == 1
    assert data_events[0].data == b'{"key": "value"}'


def test_h3_multiple_requests() -> None:
    """Client sends two requests on different streams."""
    client_quic, server_quic, h3_client, h3_server = _make_pair()
    _handshake(client_quic, server_quic)

    # Request 1 on stream 0
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
    # Request 2 on stream 4
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
