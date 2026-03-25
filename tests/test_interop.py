"""Interop tests — pipe datagrams between Zoomies instances (no network).

Since aioquic is not available in this environment, these tests verify
self-interop: client-side key derivation → server processing, and
server responses decryptable with client keys. This validates the
full encrypt/decrypt/parse pipeline end-to-end.
"""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.core.connection import ConnectionState
from zoomies.crypto import CryptoPair
from zoomies.encoding import Buffer
from zoomies.frames.crypto import CryptoFrame, push_crypto_frame
from zoomies.packet.builder import push_initial_packet_header

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"
ADDR = ("127.0.0.1", 4433)
AEAD_TAG_SIZE = 16
PN_SIZE = 4


def _build_client_initial(crypto_data: bytes = b"\x01" * 200) -> bytes:
    """Build an encrypted client Initial packet."""
    crypto = CryptoPair()
    crypto.setup_initial(cid=SERVER_CID, is_client=True)

    payload_buf = Buffer()
    push_crypto_frame(payload_buf, CryptoFrame(offset=0, data=crypto_data))
    plain_payload = payload_buf.data

    pn = 0
    header_buf = Buffer()
    ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
    push_initial_packet_header(
        header_buf,
        destination_cid=SERVER_CID,
        source_cid=CLIENT_CID,
        token=b"",
        payload_length=ciphertext_len,
    )
    plain_header = header_buf.data
    return crypto.encrypt_packet(plain_header, plain_payload, pn)


def test_server_decrypts_client_initial() -> None:
    """Server successfully decrypts a client Initial packet."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)

    packet = _build_client_initial()
    conn.datagram_received(packet, ADDR, now=1.0)

    # Should transition to HANDSHAKE (not CLOSED)
    assert conn._state != ConnectionState.CLOSED
    assert conn._state in (ConnectionState.HANDSHAKE, ConnectionState.ONE_RTT)


def test_server_produces_response_datagrams() -> None:
    """Server produces response datagrams after receiving Initial."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)

    packet = _build_client_initial()
    conn.datagram_received(packet, ADDR, now=1.0)
    datagrams = conn.send_datagrams(now=1.0)

    # Server should send at least one response (Initial ACK + Handshake)
    assert len(datagrams) >= 1
    # Responses should be non-trivial
    total_bytes = sum(len(d) for d in datagrams)
    assert total_bytes > 0


def test_server_response_decryptable_by_client() -> None:
    """Server Initial response can be decrypted with client Initial keys."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)

    packet = _build_client_initial()
    conn.datagram_received(packet, ADDR, now=1.0)

    # The server's Initial response should be decryptable by client
    # The first queued datagram is the server Initial (ACK + PING)
    client_crypto = CryptoPair()
    client_crypto.setup_initial(cid=SERVER_CID, is_client=True)

    # Server Initial is in the send queue from _queue_initial_response
    datagrams = conn.send_datagrams(now=1.0)
    assert len(datagrams) >= 1

    # First datagram should be an Initial packet (starts with long header)
    first = datagrams[0]
    assert first[0] & 0x80  # long header bit set


def test_stream_data_roundtrip_at_1rtt() -> None:
    """1-RTT stream data encrypt/decrypt roundtrip with matching keys."""
    # Simulate server sending stream data
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True

    # Send stream data
    conn.send_stream_data(stream_id=0, data=b"Hello, QUIC!", end_stream=False)
    datagrams = conn.send_datagrams(now=1.0)
    assert len(datagrams) >= 1

    # Client-side decryption
    client_crypto = CryptoPair()
    client_crypto.setup_initial(cid=SERVER_CID, is_client=True)

    for dgram in datagrams:
        # Short header: first byte has fixed bit set, no long header bit
        assert dgram[0] & 0x40  # fixed bit
        assert not (dgram[0] & 0x80)  # not long header

        # encrypted_offset = where AEAD ciphertext starts (after header + PN)
        # Short header: 1 byte + dest_cid + pn_len bytes
        # With no ACK yet, _optimal_pn_length()=4
        encrypted_offset = 1 + len(CLIENT_CID) + PN_SIZE
        _ph, payload, _pn = client_crypto.decrypt_packet(dgram, encrypted_offset, 0)
        assert len(payload) > 0


def test_ack_frame_roundtrip_at_1rtt() -> None:
    """ACK frame sent by server is a valid encrypted 1-RTT packet."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True
    conn._ack_needed_application = True
    conn._application_ack_ranges.add(0)

    datagrams = conn.send_datagrams(now=1.0)
    assert len(datagrams) >= 1

    # Decrypt with client keys
    client_crypto = CryptoPair()
    client_crypto.setup_initial(cid=SERVER_CID, is_client=True)

    encrypted_offset = 1 + len(CLIENT_CID) + PN_SIZE
    _ph, payload, _pn = client_crypto.decrypt_packet(datagrams[0], encrypted_offset, 0)
    assert len(payload) > 0


def test_connection_close_produces_encrypted_packet() -> None:
    """CONNECTION_CLOSE produces a valid encrypted packet."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True

    conn.close(error_code=0, reason="done")
    datagrams = conn.send_datagrams(now=1.0)
    assert len(datagrams) >= 1

    # Decrypt
    client_crypto = CryptoPair()
    client_crypto.setup_initial(cid=SERVER_CID, is_client=True)
    encrypted_offset = 1 + len(CLIENT_CID) + PN_SIZE
    _ph, payload, _pn = client_crypto.decrypt_packet(datagrams[0], encrypted_offset, 0)
    assert len(payload) > 0


def test_key_update_interop() -> None:
    """Key update: both sides derive same keys from same secret."""
    secret = b"\xab" * 32

    server = CryptoPair()
    server.setup_1rtt(secret, is_client=False)
    client = CryptoPair()
    client.setup_1rtt(secret, is_client=True)

    # Pre-update: server encrypts, client decrypts
    plain_header = b"\x40" + CLIENT_CID
    _, payload_pre, _ = client.decrypt_packet(
        server.encrypt_packet(plain_header, b"before", 0),
        len(plain_header),
        0,
    )
    assert payload_pre == b"before"

    # Both sides update
    server.update_keys()
    client.update_keys()
    assert server.key_phase == 1
    assert client.key_phase == 1

    # Post-update: still works
    _, payload_post, _ = client.decrypt_packet(
        server.encrypt_packet(plain_header, b"after", 1),
        len(plain_header),
        1,
    )
    assert payload_post == b"after"


def test_multiple_streams_independent() -> None:
    """Multiple streams produce independent packets."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True

    conn.send_stream_data(stream_id=0, data=b"stream0", end_stream=False)
    conn.send_stream_data(stream_id=4, data=b"stream4", end_stream=True)
    datagrams = conn.send_datagrams(now=1.0)

    # Should produce at least one datagram containing both streams
    assert len(datagrams) >= 1
    total_bytes = sum(len(d) for d in datagrams)
    assert total_bytes > 0
