"""Server-side 0-RTT packet processing at the connection layer — Sprint 3."""

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.crypto import CryptoPair
from zoomies.crypto.tls import (
    QuicClientTlsContext,
    QuicTlsContext,
    SessionTicket,
)
from zoomies.encoding import Buffer
from zoomies.events import (
    DecryptionFailed,
    StreamDataReceived,
)
from zoomies.frames.stream import StreamFrame, push_stream_frame
from zoomies.packet.builder import push_zero_rtt_packet_header
from zoomies.primitives import StreamId

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)
PN_SIZE = 4
AEAD_TAG_SIZE = 16


# --- Helpers ---


class AcceptAll:
    """ZeroRttPolicy that accepts all 0-RTT."""

    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        return True


class RejectAll:
    """ZeroRttPolicy that rejects all 0-RTT."""

    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        return False


def _transfer(sender: QuicConnection, receiver: QuicConnection) -> list:
    """Shuttle all datagrams from sender to receiver; return all events."""
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, ADDR))
    return events


def _handshake(client: QuicConnection, server: QuicConnection) -> None:
    """Complete full handshake."""
    client.connect()
    _transfer(client, server)
    _transfer(server, client)
    _transfer(client, server)
    _transfer(server, client)


def _find_message_end(data: bytes, offset: int) -> int:
    msg_len = int.from_bytes(data[offset + 1 : offset + 4], "big")
    return offset + 4 + msg_len


def _tls_handshake_with_ticket() -> tuple[SessionTicket, SessionTicket]:
    """Run full TLS handshake + ticket exchange. Returns (server_ticket, client_ticket)."""
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


def _psk_handshake_and_0rtt_keys(
    server_ticket: SessionTicket, client_ticket: SessionTicket
) -> tuple[bytes, bytes]:
    """Run PSK handshake at TLS layer, return (early_secret, client_hello_hash)."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx.add_session_ticket(server_ticket)
    client_ctx = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)
    ch = client_ctx.build_client_hello()
    sr = server_ctx.receive(ch)
    assert sr.is_psk
    assert sr.early_secret is not None
    assert sr.client_hello_hash is not None
    return sr.early_secret, sr.client_hello_hash


# --- TLS layer: client_hello_hash exposed ---


def test_server_tls_exposes_client_hello_hash() -> None:
    """TLS result includes client_hello_hash when processing ClientHello."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()
    _early_secret, ch_hash = _psk_handshake_and_0rtt_keys(server_ticket, client_ticket)
    assert len(ch_hash) == 32
    assert ch_hash != bytes(32)


def test_client_tls_exposes_client_hello_hash() -> None:
    """Client TLS result includes client_hello_hash after PSK ServerHello."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx.add_session_ticket(server_ticket)
    client_ctx = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)
    ch = client_ctx.build_client_hello()
    sr = server_ctx.receive(ch)
    flight = sr.data_to_send
    sh_end = _find_message_end(flight, 0)
    client_result = client_ctx.receive(flight[:sh_end])
    assert client_result.client_hello_hash is not None
    assert client_result.client_hello_hash == sr.client_hello_hash


# --- ZeroRttPolicy ---


def test_zero_rtt_policy_accept_all() -> None:
    """AcceptAll policy returns True."""
    policy = AcceptAll()
    assert policy.allow_0rtt(b"ticket", 0) is True


def test_zero_rtt_policy_reject_all() -> None:
    """RejectAll policy returns False."""
    policy = RejectAll()
    assert policy.allow_0rtt(b"ticket", 0) is False


def test_no_policy_means_no_0rtt() -> None:
    """Without a zero_rtt_policy, server never sets up 0-RTT crypto."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    server = QuicConnection(server_config)
    server.add_session_ticket(server_ticket)

    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    _handshake(client, server)

    # Server should NOT have 0-RTT crypto (no policy)
    assert server._zero_rtt_crypto is None


def test_reject_policy_means_no_0rtt() -> None:
    """With RejectAll policy, server never sets up 0-RTT crypto."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, zero_rtt_policy=RejectAll()
    )
    server = QuicConnection(server_config)
    server.add_session_ticket(server_ticket)

    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    _handshake(client, server)

    assert server._zero_rtt_crypto is None


def test_accept_policy_sets_up_0rtt_crypto() -> None:
    """With AcceptAll policy and PSK resumption, server sets up 0-RTT crypto."""
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
    _transfer(client, server)

    # After processing ClientHello with PSK, server should have 0-RTT crypto
    assert server._zero_rtt_crypto is not None


# --- 0-RTT packet decryption ---


def _build_0rtt_packet(
    dest_cid: bytes,
    src_cid: bytes,
    crypto: CryptoPair,
    stream_id: int,
    data: bytes,
    pn: int = 0,
    offset: int = 0,
) -> bytes:
    """Build a 0-RTT packet containing a STREAM frame."""
    payload_buf = Buffer()
    push_stream_frame(
        payload_buf,
        StreamFrame(stream_id=StreamId(stream_id), offset=offset, data=data, fin=False),
    )
    plain_payload = payload_buf.data
    ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
    header_buf = Buffer()
    push_zero_rtt_packet_header(
        header_buf,
        destination_cid=dest_cid,
        source_cid=src_cid,
        payload_length=ciphertext_len,
    )
    plain_header = header_buf.data
    return crypto.encrypt_packet(plain_header, plain_payload, pn)


def test_server_decrypts_0rtt_packet() -> None:
    """Server with 0-RTT crypto can decrypt a 0-RTT packet and deliver stream data."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    # Do PSK handshake at TLS level to get early_secret + CH hash
    server_tls = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_tls.add_session_ticket(server_ticket)
    client_tls = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)
    ch = client_tls.build_client_hello()
    sr = server_tls.receive(ch)
    assert sr.is_psk and sr.early_secret and sr.client_hello_hash

    # Set up client 0-RTT crypto
    client_0rtt = CryptoPair()
    client_0rtt.setup_0rtt(sr.early_secret, sr.client_hello_hash, is_client=True)

    # Set up server 0-RTT crypto
    server_0rtt = CryptoPair()
    server_0rtt.setup_0rtt(sr.early_secret, sr.client_hello_hash, is_client=False)

    # Build a 0-RTT packet from client
    dest_cid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    src_cid = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"
    pkt = _build_0rtt_packet(dest_cid, src_cid, client_0rtt, stream_id=0, data=b"early hello")

    # Create a server connection and manually inject 0-RTT crypto
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll()
    )
    server = QuicConnection(server_config)
    server._our_cid = dest_cid
    server._our_cids = {dest_cid}
    server._peer_cid = src_cid
    server._zero_rtt_crypto = server_0rtt
    server._state = server._state  # INITIAL

    events = server.datagram_received(pkt, ADDR)
    stream_events = [e for e in events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) == 1
    assert stream_events[0].data == b"early hello"
    assert stream_events[0].is_0rtt is True


def test_server_rejects_0rtt_without_crypto() -> None:
    """Without 0-RTT crypto, server ignores 0-RTT packets (no crash)."""
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    server = QuicConnection(server_config)
    server._our_cid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    server._our_cids = {server._our_cid}

    # Build a fake 0-RTT packet (will be ignored since no crypto)
    header_buf = Buffer()
    push_zero_rtt_packet_header(
        header_buf,
        destination_cid=server._our_cid,
        source_cid=b"\xaa\xbb\xcc\xdd",
        payload_length=50,
    )
    pkt = header_buf.data + b"\x00" * 50

    events = server.datagram_received(pkt, ADDR)
    # No crash, no stream events — packet silently dropped
    stream_events = [e for e in events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) == 0


def test_0rtt_wrong_keys_produces_decryption_failed() -> None:
    """0-RTT packet encrypted with wrong keys produces DecryptionFailed event."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()

    server_tls = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_tls.add_session_ticket(server_ticket)
    client_tls = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)
    ch = client_tls.build_client_hello()
    sr = server_tls.receive(ch)

    # Server 0-RTT crypto with correct keys
    server_0rtt = CryptoPair()
    server_0rtt.setup_0rtt(sr.early_secret, sr.client_hello_hash, is_client=False)

    # Client 0-RTT crypto with WRONG keys
    wrong_0rtt = CryptoPair()
    wrong_0rtt.setup_0rtt(bytes(32), sr.client_hello_hash, is_client=True)

    dest_cid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    src_cid = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"
    pkt = _build_0rtt_packet(dest_cid, src_cid, wrong_0rtt, stream_id=0, data=b"bad data")

    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll()
    )
    server = QuicConnection(server_config)
    server._our_cid = dest_cid
    server._our_cids = {dest_cid}
    server._peer_cid = src_cid
    server._zero_rtt_crypto = server_0rtt

    events = server.datagram_received(pkt, ADDR)
    assert any(isinstance(e, DecryptionFailed) for e in events)
    stream_events = [e for e in events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) == 0


def test_0rtt_multiple_packets_increment_pn() -> None:
    """Multiple 0-RTT packets with incrementing PNs are all decrypted."""
    server_ticket, client_ticket = _tls_handshake_with_ticket()
    server_tls = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_tls.add_session_ticket(server_ticket)
    client_tls = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)
    ch = client_tls.build_client_hello()
    sr = server_tls.receive(ch)

    client_0rtt = CryptoPair()
    client_0rtt.setup_0rtt(sr.early_secret, sr.client_hello_hash, is_client=True)
    server_0rtt = CryptoPair()
    server_0rtt.setup_0rtt(sr.early_secret, sr.client_hello_hash, is_client=False)

    dest_cid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    src_cid = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"

    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, zero_rtt_policy=AcceptAll()
    )
    server = QuicConnection(server_config)
    server._our_cid = dest_cid
    server._our_cids = {dest_cid}
    server._peer_cid = src_cid
    server._zero_rtt_crypto = server_0rtt

    stream_offset = 0
    for pn in range(3):
        payload = f"packet {pn}".encode()
        pkt = _build_0rtt_packet(
            dest_cid, src_cid, client_0rtt,
            stream_id=0, data=payload, pn=pn, offset=stream_offset,
        )
        stream_offset += len(payload)
        events = server.datagram_received(pkt, ADDR)
        stream_events = [e for e in events if isinstance(e, StreamDataReceived)]
        assert len(stream_events) == 1
        assert stream_events[0].data == payload
        assert stream_events[0].is_0rtt is True


def test_session_ticket_wired_to_client_connect() -> None:
    """QuicConfiguration.session_ticket is passed to the client TLS context."""
    _server_ticket, client_ticket = _tls_handshake_with_ticket()

    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, session_ticket=client_ticket
    )
    client = QuicConnection(client_config)
    client.connect()

    # The client TLS context should have the session ticket
    assert client._client_tls_ctx is not None
    assert client._client_tls_ctx._session_ticket is client_ticket
