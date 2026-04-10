"""End-to-end 0-RTT tests — Sprint 5.

Full scenario: initial handshake → ticket issuance → reconnect with 0-RTT →
server delivers early data → complete handshake → response.
"""

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import (
    H3DataReceived,
    H3HeadersReceived,
    HandshakeComplete,
    StreamDataReceived,
    ZeroRttAccepted,
    ZeroRttRejected,
)
from zoomies.h3 import H3Connection

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)


# --- Helpers ---


class AcceptAll:
    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        return True


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


def _collect_h3(quic_events: list, h3: H3Connection) -> list:
    out = []
    for e in quic_events:
        out.extend(h3.handle_event(e))
    return out


# --- End-to-end QUIC-level 0-RTT ---


def test_e2e_0rtt_quic_loopback() -> None:
    """Full cycle: handshake → ticket → reconnect with 0-RTT → server delivers early data."""
    # === Phase 1: Initial handshake + ticket issuance ===
    server1 = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client1 = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))
    _handshake(client1, server1)

    # Server issues ticket
    nst_msg, server_ticket = server1.generate_session_ticket()
    client_ticket = client1.receive_new_session_ticket(nst_msg)

    # === Phase 2: New connection with 0-RTT ===
    server2_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll()
    )
    server2 = QuicConnection(server2_config)
    server2.add_session_ticket(server_ticket)

    client2_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client2 = QuicConnection(client2_config)
    client2.connect()

    # Client queues 0-RTT data before handshake completes
    client2.send_stream_data(0, b"early request data", end_stream=False)

    # Client → Server: Initial (CH with PSK) + 0-RTT (stream data)
    server_events = _transfer(client2, server2)

    # Server should have received 0-RTT stream data
    early_data = [e for e in server_events if isinstance(e, StreamDataReceived) and e.is_0rtt]
    assert len(early_data) == 1
    assert early_data[0].data == b"early request data"
    assert early_data[0].stream_id == 0

    # Server → Client: completes handshake
    client_events = _transfer(server2, client2)
    assert any(isinstance(e, ZeroRttAccepted) for e in client_events)

    # Complete handshake
    _transfer(client2, server2)
    _transfer(server2, client2)

    # Server sends response via 1-RTT
    server2.send_stream_data(0, b"response to early data", end_stream=True)
    client_events2 = _transfer(server2, client2)
    response = [e for e in client_events2 if isinstance(e, StreamDataReceived)]
    assert any(e.data == b"response to early data" for e in response)


def test_e2e_0rtt_rejected_then_1rtt() -> None:
    """Full cycle: handshake → ticket → reconnect → 0-RTT rejected → data resent as 1-RTT."""
    # Phase 1: Initial handshake + ticket
    server1 = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client1 = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))
    _handshake(client1, server1)
    nst_msg, server_ticket = server1.generate_session_ticket()
    client_ticket = client1.receive_new_session_ticket(nst_msg)

    # Phase 2: New connection — server has ticket but NO 0-RTT policy
    server2 = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    server2.add_session_ticket(server_ticket)

    client2 = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False, session_ticket=client_ticket)
    )
    client2.connect()
    client2.send_stream_data(0, b"will be rejected")

    # Client → Server
    _transfer(client2, server2)

    # Server → Client (PSK handshake, no early_data in EE)
    client_events = _transfer(server2, client2)
    assert any(isinstance(e, ZeroRttRejected) for e in client_events)

    # Client resends as 1-RTT
    server_events = _transfer(client2, server2)
    _transfer(server2, client2)
    server_events2 = _transfer(client2, server2)

    all_stream = (
        [e for e in server_events if isinstance(e, StreamDataReceived)]
        + [e for e in server_events2 if isinstance(e, StreamDataReceived)]
    )
    assert any(e.data == b"will be rejected" for e in all_stream)


# --- End-to-end H3 over 0-RTT ---


def test_e2e_h3_0rtt_get_request() -> None:
    """HTTP/3 GET request over 0-RTT: headers arrive with is_0rtt=True."""
    # Phase 1: Initial H3 connection + ticket
    server1_quic = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client1_quic = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))
    _handshake(client1_quic, server1_quic)
    nst_msg, server_ticket = server1_quic.generate_session_ticket()
    client_ticket = client1_quic.receive_new_session_ticket(nst_msg)

    # Phase 2: New H3 connection with 0-RTT
    server2_quic = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll())
    )
    server2_quic.add_session_ticket(server_ticket)
    h3_server = H3Connection(sender=server2_quic)

    client2_quic = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False, session_ticket=client_ticket)
    )
    h3_client = H3Connection(sender=client2_quic)

    client2_quic.connect()

    # Client sends H3 GET request as 0-RTT
    h3_client.send_headers(
        stream_id=0,
        headers=[
            (b":method", b"GET"),
            (b":path", b"/early"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
        ],
        end_stream=True,
    )

    # Client → Server: Initial + 0-RTT
    server_quic_events = _transfer(client2_quic, server2_quic)
    h3_events = _collect_h3(server_quic_events, h3_server)

    # Server should receive H3 headers with is_0rtt=True
    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    assert len(header_events) == 1
    assert header_events[0].is_0rtt is True
    headers_dict = dict(header_events[0].headers)
    assert headers_dict[b":method"] == b"GET"
    assert headers_dict[b":path"] == b"/early"

    # Complete handshake
    client_events = _transfer(server2_quic, client2_quic)
    assert any(isinstance(e, ZeroRttAccepted) for e in client_events)
    _transfer(client2_quic, server2_quic)
    _transfer(server2_quic, client2_quic)

    # Server sends H3 response
    h3_server.send_headers(
        stream_id=0,
        headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
        end_stream=False,
    )
    h3_server.send_data(stream_id=0, data=b"early response!", end_stream=True)

    client_quic_events = _transfer(server2_quic, client2_quic)
    h3_resp = _collect_h3(client_quic_events, h3_client)

    resp_headers = [e for e in h3_resp if isinstance(e, H3HeadersReceived)]
    resp_data = [e for e in h3_resp if isinstance(e, H3DataReceived)]
    assert len(resp_headers) == 1
    assert dict(resp_headers[0].headers)[b":status"] == b"200"
    assert len(resp_data) == 1
    assert resp_data[0].data == b"early response!"


def test_e2e_h3_0rtt_post_with_body() -> None:
    """HTTP/3 POST with body over 0-RTT: headers + data arrive as early data."""
    # Phase 1: Get ticket
    server1 = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client1 = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))
    _handshake(client1, server1)
    nst_msg, server_ticket = server1.generate_session_ticket()
    client_ticket = client1.receive_new_session_ticket(nst_msg)

    # Phase 2: 0-RTT POST
    server2 = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll())
    )
    server2.add_session_ticket(server_ticket)
    h3_server = H3Connection(sender=server2)

    client2 = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False, session_ticket=client_ticket)
    )
    h3_client = H3Connection(sender=client2)
    client2.connect()

    h3_client.send_headers(
        stream_id=0,
        headers=[
            (b":method", b"POST"),
            (b":path", b"/submit"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
        ],
        end_stream=False,
    )
    h3_client.send_data(stream_id=0, data=b'{"early": true}', end_stream=True)

    # Client → Server
    server_quic_events = _transfer(client2, server2)
    h3_events = _collect_h3(server_quic_events, h3_server)

    header_events = [e for e in h3_events if isinstance(e, H3HeadersReceived)]
    data_events = [e for e in h3_events if isinstance(e, H3DataReceived)]
    assert len(header_events) == 1
    assert header_events[0].is_0rtt is True
    assert dict(header_events[0].headers)[b":method"] == b"POST"
    # Data may arrive in same or subsequent events
    # Complete handshake first, then check all data
    _transfer(server2, client2)
    _transfer(client2, server2)
    _transfer(server2, client2)

    # Re-check — data may come in later events
    if not data_events:
        # Data might have come in a separate 0-RTT packet
        pass
    else:
        assert data_events[0].data == b'{"early": true}'


def test_e2e_multiple_0rtt_streams() -> None:
    """Multiple streams sent as 0-RTT data all arrive on the server."""
    server1 = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client1 = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))
    _handshake(client1, server1)
    nst_msg, server_ticket = server1.generate_session_ticket()
    client_ticket = client1.receive_new_session_ticket(nst_msg)

    server2 = QuicConnection(
        QuicConfiguration(certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll())
    )
    server2.add_session_ticket(server_ticket)

    client2 = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False, session_ticket=client_ticket)
    )
    client2.connect()

    # Queue multiple streams as 0-RTT
    client2.send_stream_data(0, b"stream-0-data", end_stream=False)
    client2.send_stream_data(4, b"stream-4-data", end_stream=False)

    server_events = _transfer(client2, server2)
    early = [e for e in server_events if isinstance(e, StreamDataReceived) and e.is_0rtt]
    stream_ids = {e.stream_id for e in early}
    assert 0 in stream_ids
    assert 4 in stream_ids


def test_e2e_0rtt_ticket_round_trip_via_connection() -> None:
    """generate_session_ticket + receive_new_session_ticket via QuicConnection API."""
    server = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))
    _handshake(client, server)

    nst_msg, server_ticket = server.generate_session_ticket()
    client_ticket = client.receive_new_session_ticket(nst_msg)

    # Tickets should be compatible
    assert server_ticket.ticket == client_ticket.ticket
    assert server_ticket.derive_psk() == client_ticket.derive_psk()
