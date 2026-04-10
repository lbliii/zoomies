"""Client-side 0-RTT send + rejection recovery — Sprint 4."""

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.crypto.tls import (
    QuicClientTlsContext,
    QuicTlsContext,
    SessionTicket,
)
from zoomies.encoding import Buffer
from zoomies.events import (
    StreamDataReceived,
    ZeroRttAccepted,
    ZeroRttRejected,
)
from zoomies.packet.header import PACKET_TYPE_ZERO_RTT, pull_quic_header

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)


# --- Helpers ---


class AcceptAll:
    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        return True


class RejectAll:
    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        return False


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


def _find_message_end(data: bytes, offset: int) -> int:
    msg_len = int.from_bytes(data[offset + 1 : offset + 4], "big")
    return offset + 4 + msg_len


def _tls_handshake_with_ticket() -> tuple[SessionTicket, SessionTicket]:
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    client_ctx = QuicClientTlsContext(verify_mode=False)
    ch = client_ctx.build_client_hello()
    sr = server_ctx.receive(ch)
    flight = sr.data_to_send
    sh_end = _find_message_end(flight, 0)
    client_ctx.receive(flight[:sh_end])
    cr = client_ctx.receive(flight[sh_end:])
    server_ctx.receive(cr.data_to_send)
    nst_msg, server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)
    return server_ticket, client_ticket


# --- Client 0-RTT crypto setup ---


def test_client_sets_up_0rtt_crypto_with_ticket() -> None:
    """Client with session ticket sets up 0-RTT crypto after connect()."""
    _server_ticket, client_ticket = _tls_handshake_with_ticket()
    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()
    assert client._zero_rtt_crypto is not None


def test_client_no_0rtt_without_ticket() -> None:
    """Client without session ticket does not set up 0-RTT crypto."""
    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()
    assert client._zero_rtt_crypto is None


# --- 0-RTT packet construction ---


def test_client_sends_0rtt_packets() -> None:
    """Client with 0-RTT crypto produces 0-RTT packets from send_stream_data."""
    _server_ticket, client_ticket = _tls_handshake_with_ticket()
    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()

    # Queue early data before handshake completes
    client.send_stream_data(0, b"early request", end_stream=False)

    datagrams = client.send_datagrams()
    # Should have at least 2 packets: Initial (ClientHello) + 0-RTT
    assert len(datagrams) >= 2

    # Find the 0-RTT packet
    zero_rtt_found = False
    for dg in datagrams:
        buf = Buffer(data=dg)
        try:
            header = pull_quic_header(buf, host_cid_length=8)
            from zoomies.packet.header import LongHeader

            if isinstance(header, LongHeader) and header.packet_type == PACKET_TYPE_ZERO_RTT:
                zero_rtt_found = True
                break
        except ValueError:
            continue
    assert zero_rtt_found, "Expected a 0-RTT packet in send_datagrams output"


def test_0rtt_data_routes_to_zero_rtt_queue() -> None:
    """send_stream_data routes to 0-RTT queue when crypto available pre-handshake."""
    _server_ticket, client_ticket = _tls_handshake_with_ticket()
    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()

    client.send_stream_data(0, b"early data")
    assert len(client._zero_rtt_stream_queue) == 1
    assert len(client._stream_send_queue) == 0


# --- End-to-end 0-RTT loopback ---


def test_0rtt_end_to_end_accepted() -> None:
    """Full loopback: client sends 0-RTT, server accepts and delivers data."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    # Server with AcceptAll policy
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll()
    )
    server = QuicConnection(server_config)
    server.add_session_ticket(server_ticket)

    # Client with session ticket
    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()

    # Queue early data
    client.send_stream_data(0, b"GET / HTTP/3", end_stream=False)

    # Transfer Initial + 0-RTT to server
    server_events = _transfer(client, server)

    # Server should have received 0-RTT stream data
    stream_events = [e for e in server_events if isinstance(e, StreamDataReceived)]
    zero_rtt_events = [e for e in stream_events if e.is_0rtt]
    assert len(zero_rtt_events) >= 1
    assert zero_rtt_events[0].data == b"GET / HTTP/3"


# --- TLS early_data signaling ---


def test_tls_early_data_in_encrypted_extensions() -> None:
    """When server accepts 0-RTT, EE includes early_data extension."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx.add_session_ticket(server_ticket)
    server_ctx.accept_early_data = True

    client_ctx = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)
    ch = client_ctx.build_client_hello()
    sr = server_ctx.receive(ch)
    assert sr.is_psk

    # Client processes SH + EE
    flight = sr.data_to_send
    sh_end = _find_message_end(flight, 0)
    client_ctx.receive(flight[:sh_end])  # SH
    cr = client_ctx.receive(flight[sh_end:])  # EE + Finished
    assert cr.early_data_accepted is True


def test_tls_no_early_data_without_flag() -> None:
    """Without accept_early_data, EE does not include early_data extension."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx.add_session_ticket(server_ticket)
    # accept_early_data defaults to False

    client_ctx = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)
    ch = client_ctx.build_client_hello()
    sr = server_ctx.receive(ch)
    assert sr.is_psk

    flight = sr.data_to_send
    sh_end = _find_message_end(flight, 0)
    client_ctx.receive(flight[:sh_end])
    cr = client_ctx.receive(flight[sh_end:])
    assert cr.early_data_accepted is False


# --- 0-RTT acceptance event ---


def test_0rtt_accepted_event() -> None:
    """Client emits ZeroRttAccepted when server's EE includes early_data."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll()
    )
    server = QuicConnection(server_config)
    server.add_session_ticket(server_ticket)

    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()
    client.send_stream_data(0, b"early data")

    # Client → Server
    _transfer(client, server)

    # Server → Client (SH + EE with early_data + Finished + HANDSHAKE_DONE)
    client_events = _transfer(server, client)

    accepted_events = [e for e in client_events if isinstance(e, ZeroRttAccepted)]
    assert len(accepted_events) == 1


# --- 0-RTT rejection + resend ---


def test_0rtt_rejected_event() -> None:
    """Client emits ZeroRttRejected when server's EE does not include early_data."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    # Server with NO 0-RTT policy (will do PSK but not accept early_data)
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    server = QuicConnection(server_config)
    server.add_session_ticket(server_ticket)

    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()
    client.send_stream_data(0, b"early data that will be rejected")

    # Client → Server
    _transfer(client, server)

    # Server → Client (PSK SH + EE without early_data)
    client_events = _transfer(server, client)

    rejected_events = [e for e in client_events if isinstance(e, ZeroRttRejected)]
    assert len(rejected_events) == 1
    # 0-RTT crypto should be discarded
    assert client._zero_rtt_crypto is None


def test_0rtt_rejection_resends_as_1rtt() -> None:
    """After 0-RTT rejection, client resends data as 1-RTT."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    server = QuicConnection(server_config)
    server.add_session_ticket(server_ticket)

    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()
    client.send_stream_data(0, b"retry me")

    # Client → Server (Initial + 0-RTT)
    _transfer(client, server)

    # Server → Client (SH + EE without early_data + Finished + HANDSHAKE_DONE)
    _transfer(server, client)

    # Client should have queued the rejected data for 1-RTT resend
    assert len(client._stream_send_queue) > 0

    # Client → Server (Handshake Finished + 1-RTT with resent data)
    server_events = _transfer(client, server)

    # Server → Client (ACKs — may also deliver HANDSHAKE_DONE)
    _transfer(server, client)

    # Another round if needed — client may need to receive HANDSHAKE_DONE first
    server_events2 = _transfer(client, server)
    _transfer(server, client)

    # Check that server received the data via 1-RTT (in either round)
    all_stream_events = [e for e in server_events if isinstance(e, StreamDataReceived)] + [
        e for e in server_events2 if isinstance(e, StreamDataReceived)
    ]
    assert any(e.data == b"retry me" for e in all_stream_events)


# --- Edge cases ---


def test_client_0rtt_discarded_after_rejection() -> None:
    """After rejection, client._zero_rtt_crypto is None and no more 0-RTT queuing."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    server = QuicConnection(server_config)
    server.add_session_ticket(server_ticket)

    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()
    client.send_stream_data(0, b"early")

    _transfer(client, server)
    _transfer(server, client)

    # After rejection, new data should go to 1-RTT queue
    assert client._zero_rtt_crypto is None
    client.send_stream_data(4, b"post-rejection data")
    assert len(client._zero_rtt_stream_queue) == 0
    assert any(b"post-rejection data" in item[1] for item in client._stream_send_queue)
