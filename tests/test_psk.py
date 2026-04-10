"""PSK handshake and session ticket tests — Sprint 1 of 0-RTT plan."""

import pytest

from tests.utils import load
from zoomies.crypto.tls import (
    ClientTlsState,
    QuicClientTlsContext,
    QuicTlsContext,
    SessionTicket,
    TlsHandshakeState,
    _build_new_session_ticket,
    _parse_client_hello_full,
    _parse_new_session_ticket,
    _parse_server_hello_full,
)

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")


# --- Helpers ---


def _find_message_end(data: bytes, offset: int) -> int:
    """Find the end of a TLS handshake message at offset."""
    msg_len = int.from_bytes(data[offset + 1 : offset + 4], "big")
    return offset + 4 + msg_len


def _full_handshake() -> tuple[QuicTlsContext, QuicClientTlsContext]:
    """Run a full TLS handshake. Returns (server_ctx, client_ctx)."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    client_ctx = QuicClientTlsContext(verify_mode=False)

    client_hello = client_ctx.build_client_hello()
    server_result = server_ctx.receive(client_hello)
    server_flight = server_result.data_to_send

    sh_end = _find_message_end(server_flight, 0)
    client_ctx.receive(server_flight[:sh_end])
    client_result = client_ctx.receive(server_flight[sh_end:])

    # Feed client Finished to server
    server_ctx.receive(client_result.data_to_send)
    return server_ctx, client_ctx


# --- NewSessionTicket build/parse ---


def test_new_session_ticket_roundtrip() -> None:
    """_build_new_session_ticket output parses correctly."""
    msg = _build_new_session_ticket(
        lifetime=7200,
        age_add=12345,
        nonce=b"\x00\x00\x00\x01",
        ticket=b"test-ticket-data-here",
        max_early_data=0xFFFFFFFF,
    )
    lifetime, age_add, nonce, ticket, max_early_data = _parse_new_session_ticket(msg)
    assert lifetime == 7200
    assert age_add == 12345
    assert nonce == b"\x00\x00\x00\x01"
    assert ticket == b"test-ticket-data-here"
    assert max_early_data == 0xFFFFFFFF


def test_new_session_ticket_no_early_data() -> None:
    """NewSessionTicket without early_data extension parses with max_early_data=0."""
    from zoomies.crypto.tls import HANDSHAKE_NEW_SESSION_TICKET, _push_block
    from zoomies.encoding import Buffer

    buf = Buffer()
    buf.push_uint8(HANDSHAKE_NEW_SESSION_TICKET)
    inner = Buffer()
    inner.push_uint32(3600)
    inner.push_uint32(0)
    _push_block(inner, 1, b"\x00")
    _push_block(inner, 2, b"ticket")
    _push_block(inner, 2, b"")  # empty extensions
    _push_block(buf, 3, inner.data)

    lifetime, _age_add, _nonce, ticket, max_early_data = _parse_new_session_ticket(buf.data)
    assert lifetime == 3600
    assert ticket == b"ticket"
    assert max_early_data == 0


# --- Server generates session ticket ---


def test_server_generates_session_ticket() -> None:
    """Server generates a valid session ticket after handshake."""
    server_ctx, _client_ctx = _full_handshake()

    nst_msg, ticket = server_ctx.generate_session_ticket()
    assert isinstance(ticket, SessionTicket)
    assert len(ticket.ticket) == 32
    assert ticket.lifetime == 7200
    assert ticket.resumption_secret is not None
    assert len(ticket.resumption_secret) == 32

    # Message should be parseable
    lifetime, _age_add, _nonce, ticket_data, max_early_data = _parse_new_session_ticket(nst_msg)
    assert lifetime == 7200
    assert ticket_data == ticket.ticket
    assert max_early_data == 0xFFFFFFFF


def test_server_generates_unique_tickets() -> None:
    """Each ticket has a unique nonce and ticket data."""
    server_ctx, _client_ctx = _full_handshake()

    _, ticket1 = server_ctx.generate_session_ticket()
    _, ticket2 = server_ctx.generate_session_ticket()

    assert ticket1.ticket != ticket2.ticket
    assert ticket1.nonce != ticket2.nonce


def test_server_generate_ticket_before_handshake_raises() -> None:
    """Cannot generate ticket before handshake completes."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    with pytest.raises(RuntimeError, match="no resumption secret"):
        server_ctx.generate_session_ticket()


# --- Client receives session ticket ---


def test_client_receives_session_ticket() -> None:
    """Client can parse a NewSessionTicket from the server."""
    server_ctx, client_ctx = _full_handshake()

    nst_msg, server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)

    assert isinstance(client_ticket, SessionTicket)
    assert client_ticket.ticket == server_ticket.ticket
    assert client_ticket.lifetime == server_ticket.lifetime


def test_client_ticket_derives_same_psk() -> None:
    """Client and server derive the same PSK from the same ticket."""
    server_ctx, client_ctx = _full_handshake()

    nst_msg, server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)

    # Both should derive the same PSK
    server_psk = server_ticket.derive_psk()
    client_psk = client_ticket.derive_psk()
    assert server_psk == client_psk


# --- PSK ClientHello ---


def test_psk_clienthello_has_extensions() -> None:
    """ClientHello with session ticket includes PSK extensions."""
    server_ctx, client_ctx = _full_handshake()
    nst_msg, _server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)

    # Build a new ClientHello with the ticket
    psk_client = QuicClientTlsContext(
        verify_mode=False, session_ticket=client_ticket
    )
    ch = psk_client.build_client_hello()

    # Parse and verify PSK extensions are present
    ch_info = _parse_client_hello_full(ch)
    assert 45 in ch_info.extensions  # EXT_PSK_KEY_EXCHANGE_MODES
    assert 41 in ch_info.extensions  # EXT_PRE_SHARED_KEY


# --- PSK Handshake Loopback ---


def test_psk_handshake_loopback() -> None:
    """Full PSK resumption handshake: ticket → PSK ClientHello → PSK ServerHello → Finished."""
    # Step 1: Initial handshake + get ticket
    server_ctx, client_ctx = _full_handshake()
    nst_msg, server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)

    # Step 2: New connection with PSK
    server_ctx2 = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx2.add_session_ticket(server_ticket)

    psk_client = QuicClientTlsContext(
        verify_mode=False, session_ticket=client_ticket
    )
    ch = psk_client.build_client_hello()

    # Step 3: Server processes PSK ClientHello
    server_result = server_ctx2.receive(ch)
    assert server_result.handshake_secret is not None
    assert server_result.is_psk is True

    server_flight = server_result.data_to_send
    assert len(server_flight) > 0

    # Verify server responded with PSK-selected ServerHello
    sh_end = _find_message_end(server_flight, 0)
    sh_info = _parse_server_hello_full(server_flight[:sh_end])
    assert sh_info.psk_identity == 0  # Selected our identity

    # Step 4: Client processes server flight (SH + EE + Finished — no Cert/CertVerify)
    psk_client.receive(server_flight[:sh_end])
    assert psk_client.state == ClientTlsState.WAIT_ENCRYPTED_EXTENSIONS

    client_result = psk_client.receive(server_flight[sh_end:])
    assert psk_client.state == ClientTlsState.HANDSHAKE_COMPLETE
    assert client_result.is_psk is True

    # Step 5: Verify secrets match
    assert client_result.handshake_secret == server_result.handshake_secret
    assert client_result.traffic_secret == server_result.traffic_secret

    # Step 6: Server verifies client Finished
    final_result = server_ctx2.receive(client_result.data_to_send)
    assert final_result.state == TlsHandshakeState.HANDSHAKE_COMPLETE


def test_psk_handshake_wrong_ticket_falls_back_to_full() -> None:
    """If PSK binder is wrong, server falls back to full handshake."""
    # Get a ticket from one server
    server_ctx, client_ctx = _full_handshake()
    nst_msg, _server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)

    # New server that does NOT have this ticket registered
    server_ctx2 = QuicTlsContext(certificate=CERT, private_key=KEY)
    # Don't call add_session_ticket — server doesn't know this ticket

    psk_client = QuicClientTlsContext(
        verify_mode=False, session_ticket=client_ticket
    )
    ch = psk_client.build_client_hello()

    # Server processes — should do full handshake (no PSK)
    server_result = server_ctx2.receive(ch)
    assert server_result.is_psk is False

    # ServerHello should NOT have pre_shared_key extension
    sh_end = _find_message_end(server_result.data_to_send, 0)
    sh_info = _parse_server_hello_full(server_result.data_to_send[:sh_end])
    assert sh_info.psk_identity is None


def test_psk_handshake_server_can_issue_new_ticket() -> None:
    """After PSK handshake, server can issue another ticket for next resumption."""
    # Initial handshake + ticket
    server_ctx, client_ctx = _full_handshake()
    nst_msg, server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)

    # PSK handshake
    server_ctx2 = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx2.add_session_ticket(server_ticket)
    psk_client = QuicClientTlsContext(
        verify_mode=False, session_ticket=client_ticket
    )
    ch = psk_client.build_client_hello()
    server_result = server_ctx2.receive(ch)
    server_flight = server_result.data_to_send
    sh_end = _find_message_end(server_flight, 0)
    psk_client.receive(server_flight[:sh_end])
    client_result = psk_client.receive(server_flight[sh_end:])
    server_ctx2.receive(client_result.data_to_send)

    # Server issues new ticket after PSK handshake
    nst_msg2, ticket2 = server_ctx2.generate_session_ticket()
    assert isinstance(ticket2, SessionTicket)
    assert len(ticket2.ticket) == 32

    # Client can parse the new ticket
    client_ticket2 = psk_client.receive_new_session_ticket(nst_msg2)
    assert client_ticket2.ticket == ticket2.ticket


def test_psk_flight_is_shorter_than_full() -> None:
    """PSK handshake server flight is shorter (no Certificate/CertificateVerify)."""
    # Full handshake
    full_server = QuicTlsContext(certificate=CERT, private_key=KEY)
    full_client = QuicClientTlsContext(verify_mode=False)
    ch = full_client.build_client_hello()
    full_result = full_server.receive(ch)
    full_flight_len = len(full_result.data_to_send)

    # PSK handshake
    server_ctx, client_ctx = _full_handshake()
    nst_msg, server_ticket = server_ctx.generate_session_ticket()
    client_ticket = client_ctx.receive_new_session_ticket(nst_msg)

    psk_server = QuicTlsContext(certificate=CERT, private_key=KEY)
    psk_server.add_session_ticket(server_ticket)
    psk_client = QuicClientTlsContext(
        verify_mode=False, session_ticket=client_ticket
    )
    psk_ch = psk_client.build_client_hello()
    psk_result = psk_server.receive(psk_ch)
    psk_flight_len = len(psk_result.data_to_send)

    # PSK flight should be significantly shorter (no cert chain)
    assert psk_flight_len < full_flight_len
