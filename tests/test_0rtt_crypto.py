"""0-RTT key derivation and encrypt/decrypt — Sprint 2 of 0-RTT plan."""

import pytest
from cryptography.hazmat.primitives import hashes

from tests.utils import load
from zoomies.crypto._hkdf import hkdf_expand_label, hkdf_extract
from zoomies.crypto.quic_crypto import CryptoPair
from zoomies.crypto.tls import (
    QuicClientTlsContext,
    QuicTlsContext,
    SessionTicket,
)

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")


# --- Helpers ---


def _find_message_end(data: bytes, offset: int) -> int:
    msg_len = int.from_bytes(data[offset + 1 : offset + 4], "big")
    return offset + 4 + msg_len


def _full_handshake_with_ticket() -> tuple[SessionTicket, SessionTicket]:
    """Run full handshake + ticket exchange. Returns (server_ticket, client_ticket)."""
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


def _psk_handshake_with_early_secret(
    server_ticket: SessionTicket, client_ticket: SessionTicket
) -> tuple[bytes, bytes]:
    """Run PSK handshake, return (early_secret, client_hello_hash)."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx.add_session_ticket(server_ticket)
    client_ctx = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)

    ch = client_ctx.build_client_hello()

    # Compute client_hello_hash (hash of just the ClientHello message)
    ch_hash = hashes.Hash(hashes.SHA256())
    ch_hash.update(ch)
    client_hello_hash = ch_hash.finalize()

    sr = server_ctx.receive(ch)
    assert sr.is_psk is True
    assert sr.early_secret is not None

    # Both sides should have the same early_secret
    flight = sr.data_to_send
    sh_end = _find_message_end(flight, 0)
    client_sh_result = client_ctx.receive(flight[:sh_end])
    assert client_sh_result.early_secret is not None
    assert client_sh_result.early_secret == sr.early_secret

    return sr.early_secret, client_hello_hash


# --- Early secret derivation ---


def test_early_secret_from_psk() -> None:
    """Early secret is correctly derived from PSK (non-zero)."""
    server_ticket, client_ticket = _full_handshake_with_ticket()
    psk = client_ticket.derive_psk()

    # Manual derivation
    expected = hkdf_extract(hashes.SHA256, bytes(32), psk)
    assert expected != hkdf_extract(hashes.SHA256, bytes(32), bytes(32))  # Not zero PSK

    # Via PSK handshake
    early_secret, _ch_hash = _psk_handshake_with_early_secret(server_ticket, client_ticket)
    assert early_secret == expected


def test_early_secret_matches_between_client_and_server() -> None:
    """Client and server derive identical early_secret during PSK handshake."""
    server_ticket, client_ticket = _full_handshake_with_ticket()
    early_secret, _ = _psk_handshake_with_early_secret(server_ticket, client_ticket)
    assert len(early_secret) == 32


def test_client_early_traffic_secret_derivation() -> None:
    """client_early_traffic_secret is derivable from early_secret + CH hash."""
    server_ticket, client_ticket = _full_handshake_with_ticket()
    early_secret, ch_hash = _psk_handshake_with_early_secret(server_ticket, client_ticket)

    # Derive manually
    cets = hkdf_expand_label(hashes.SHA256, early_secret, b"c e traffic", ch_hash, 32)
    assert len(cets) == 32
    assert cets != bytes(32)


# --- CryptoPair.setup_0rtt ---


def test_setup_0rtt_client_can_encrypt() -> None:
    """Client-side 0-RTT CryptoPair can encrypt packets."""
    server_ticket, client_ticket = _full_handshake_with_ticket()
    early_secret, ch_hash = _psk_handshake_with_early_secret(server_ticket, client_ticket)

    client_pair = CryptoPair()
    client_pair.setup_0rtt(early_secret, ch_hash, is_client=True)

    # Encrypt a packet
    header = bytes([0xC0 | 0x10, 0x00, 0x00, 0x01])  # 0-RTT long header stub
    payload = b"hello 0-RTT world"
    encrypted = client_pair.encrypt_packet(header, payload, packet_number=0)
    assert encrypted != header + payload
    assert len(encrypted) > len(header)


def test_setup_0rtt_server_can_decrypt() -> None:
    """Server-side 0-RTT CryptoPair can decrypt what client encrypted."""
    server_ticket, client_ticket = _full_handshake_with_ticket()
    early_secret, ch_hash = _psk_handshake_with_early_secret(server_ticket, client_ticket)

    client_pair = CryptoPair()
    client_pair.setup_0rtt(early_secret, ch_hash, is_client=True)

    server_pair = CryptoPair()
    server_pair.setup_0rtt(early_secret, ch_hash, is_client=False)

    # Client encrypts
    header = bytes([0xC0 | 0x10, 0x00, 0x00, 0x01])
    payload = b"early data from client"
    encrypted = client_pair.encrypt_packet(header, payload, packet_number=0)

    # Server decrypts
    _plain_header, plain_payload, pn = server_pair.decrypt_packet(
        encrypted, encrypted_offset=len(header), expected_packet_number=0
    )
    assert plain_payload == payload
    assert pn == 0


def test_0rtt_encrypt_decrypt_multiple_packets() -> None:
    """Multiple 0-RTT packets encrypt/decrypt with incrementing PNs."""
    server_ticket, client_ticket = _full_handshake_with_ticket()
    early_secret, ch_hash = _psk_handshake_with_early_secret(server_ticket, client_ticket)

    client_pair = CryptoPair()
    client_pair.setup_0rtt(early_secret, ch_hash, is_client=True)
    server_pair = CryptoPair()
    server_pair.setup_0rtt(early_secret, ch_hash, is_client=False)

    header = bytes([0xC0 | 0x10, 0x00, 0x00, 0x01])
    for pn in range(5):
        payload = f"packet {pn}".encode()
        encrypted = client_pair.encrypt_packet(header, payload, packet_number=pn)
        _, decrypted, got_pn = server_pair.decrypt_packet(
            encrypted, encrypted_offset=len(header), expected_packet_number=pn
        )
        assert decrypted == payload
        assert got_pn == pn


def test_0rtt_keys_differ_from_1rtt_keys() -> None:
    """0-RTT keys are distinct from 1-RTT keys derived in the same handshake."""
    server_ticket, client_ticket = _full_handshake_with_ticket()

    # Do full PSK handshake to get both early_secret and traffic_secret
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    server_ctx.add_session_ticket(server_ticket)
    client_ctx = QuicClientTlsContext(verify_mode=False, session_ticket=client_ticket)

    ch = client_ctx.build_client_hello()
    ch_hash_obj = hashes.Hash(hashes.SHA256())
    ch_hash_obj.update(ch)
    ch_hash = ch_hash_obj.finalize()

    sr = server_ctx.receive(ch)
    flight = sr.data_to_send
    sh_end = _find_message_end(flight, 0)
    client_ctx.receive(flight[:sh_end])
    cr = client_ctx.receive(flight[sh_end:])

    early_secret = sr.early_secret
    traffic_secret = cr.traffic_secret
    assert early_secret is not None
    assert traffic_secret is not None

    # Set up both crypto pairs
    zero_rtt = CryptoPair()
    zero_rtt.setup_0rtt(early_secret, ch_hash, is_client=True)

    one_rtt = CryptoPair()
    one_rtt.setup_1rtt(traffic_secret, is_client=True)

    # Encrypt same payload — ciphertexts should differ
    header = bytes([0xC0, 0x00, 0x00, 0x01])
    payload = b"same payload"
    ct_0rtt = zero_rtt.encrypt_packet(header, payload, packet_number=0)
    ct_1rtt = one_rtt.encrypt_packet(header, payload, packet_number=0)
    assert ct_0rtt != ct_1rtt


def test_0rtt_wrong_key_fails_decrypt() -> None:
    """Decrypting 0-RTT with wrong keys raises."""
    from cryptography.exceptions import InvalidTag

    server_ticket, client_ticket = _full_handshake_with_ticket()
    early_secret, ch_hash = _psk_handshake_with_early_secret(server_ticket, client_ticket)

    client_pair = CryptoPair()
    client_pair.setup_0rtt(early_secret, ch_hash, is_client=True)

    # Set up server with WRONG early_secret
    wrong_pair = CryptoPair()
    wrong_pair.setup_0rtt(bytes(32), ch_hash, is_client=False)

    header = bytes([0xC0 | 0x10, 0x00, 0x00, 0x01])
    encrypted = client_pair.encrypt_packet(header, b"secret data", packet_number=0)

    with pytest.raises(InvalidTag):
        wrong_pair.decrypt_packet(encrypted, encrypted_offset=len(header), expected_packet_number=0)
