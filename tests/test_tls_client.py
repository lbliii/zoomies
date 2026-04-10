"""TLS 1.3 client handshake — roundtrip with server."""

import pytest

from tests.utils import load
from zoomies.crypto.tls import (
    ClientTlsState,
    QuicClientTlsContext,
    QuicTlsContext,
    TlsHandshakeState,
    _build_client_hello,
    _parse_client_hello,
    _parse_server_hello,
)

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")


# --- QuicClientTlsContext unit tests ---


def test_client_initial_state() -> None:
    """Client TLS context starts in START state."""
    ctx = QuicClientTlsContext()
    assert ctx.state == ClientTlsState.START


def test_client_build_client_hello() -> None:
    """build_client_hello produces valid ClientHello bytes."""
    ctx = QuicClientTlsContext()
    msg = ctx.build_client_hello()
    assert msg[0] == 0x01  # ClientHello handshake type
    assert ctx.state == ClientTlsState.WAIT_SERVER_HELLO
    # Should be parseable by the server's parser
    random, session_id, key_share = _parse_client_hello(msg)
    assert len(random) == 32
    assert len(session_id) == 32
    assert len(key_share) >= 1
    # First key share should be X25519
    assert key_share[0][0] == 0x001D  # GROUP_X25519
    assert len(key_share[0][1]) == 32


def test_client_build_client_hello_only_once() -> None:
    """build_client_hello raises if called twice."""
    ctx = QuicClientTlsContext()
    ctx.build_client_hello()
    with pytest.raises(RuntimeError, match="already called"):
        ctx.build_client_hello()


def test_client_build_client_hello_with_sni() -> None:
    """ClientHello includes SNI extension when server_name is set."""
    ctx = QuicClientTlsContext(server_name="example.com")
    msg = ctx.build_client_hello()
    # SNI extension should be present in the raw bytes
    assert b"example.com" in msg


# --- _build_client_hello / _parse_client_hello roundtrip ---


def test_build_parse_client_hello_roundtrip() -> None:
    """_build_client_hello output parses correctly with _parse_client_hello."""
    import os

    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    random = os.urandom(32)
    session_id = os.urandom(32)
    msg = _build_client_hello(random, session_id, (0x001D, pub), server_name="test.local")
    parsed_random, parsed_sid, parsed_ks = _parse_client_hello(msg)
    assert parsed_random == random
    assert parsed_sid == session_id
    assert any(group == 0x001D for group, _ in parsed_ks)


# --- _parse_server_hello ---


def test_parse_server_hello_from_real_server() -> None:
    """Server's response to ClientHello parses correctly."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    client_ctx = QuicClientTlsContext()
    client_hello = client_ctx.build_client_hello()
    result = server_ctx.receive(client_hello)
    # Server response starts with ServerHello
    server_hello_end = _find_message_end(result.data_to_send, 0)
    server_hello_bytes = result.data_to_send[:server_hello_end]
    random, _session_id, key_share = _parse_server_hello(server_hello_bytes)
    assert len(random) == 32
    assert key_share[0] == 0x001D  # X25519
    assert len(key_share[1]) == 32


# --- Full TLS roundtrip ---


def test_tls_client_server_roundtrip() -> None:
    """Full TLS handshake: client builds CH → server responds → client processes → secrets match."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    client_ctx = QuicClientTlsContext(verify_mode=False)

    # Step 1: Client builds ClientHello
    client_hello = client_ctx.build_client_hello()
    assert client_ctx.state == ClientTlsState.WAIT_SERVER_HELLO

    # Step 2: Server processes ClientHello, produces server flight
    server_result = server_ctx.receive(client_hello)
    assert server_result.handshake_secret is not None
    assert server_result.traffic_secret is not None
    server_flight = server_result.data_to_send
    assert len(server_flight) > 0

    # Step 3: Client processes ServerHello (first message in server flight)
    # The server flight contains: ServerHello + EE + Certificate + CertificateVerify + Finished
    # In QUIC, ServerHello goes in Initial CRYPTO, rest in Handshake CRYPTO.
    # At TLS layer, we feed them to the client as one blob.
    # But the client needs handshake keys from ServerHello BEFORE decrypting the rest.
    # Split: feed ServerHello first, then the rest.
    sh_end = _find_message_end(server_flight, 0)
    server_hello_bytes = server_flight[:sh_end]
    encrypted_flight = server_flight[sh_end:]

    client_result_sh = client_ctx.receive(server_hello_bytes)
    assert client_result_sh.handshake_secret is not None
    assert client_ctx.state == ClientTlsState.WAIT_ENCRYPTED_EXTENSIONS

    # Step 4: Client processes remaining server flight (EE + Cert + CertVerify + Finished)
    client_result = client_ctx.receive(encrypted_flight)
    assert client_ctx.state == ClientTlsState.HANDSHAKE_COMPLETE
    assert client_result.traffic_secret is not None
    assert len(client_result.data_to_send) > 0  # client Finished

    # Step 5: Verify both sides derived matching secrets
    assert client_result_sh.handshake_secret == server_result.handshake_secret
    assert client_result.traffic_secret == server_result.traffic_secret


def test_tls_client_server_roundtrip_with_cert_verification() -> None:
    """Roundtrip with certificate verification enabled."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    # Use the cert itself as CA (self-signed)
    client_ctx = QuicClientTlsContext(ca_certs=CERT, verify_mode=True)

    client_hello = client_ctx.build_client_hello()
    server_result = server_ctx.receive(client_hello)

    sh_end = _find_message_end(server_result.data_to_send, 0)
    client_ctx.receive(server_result.data_to_send[:sh_end])
    client_result = client_ctx.receive(server_result.data_to_send[sh_end:])

    assert client_ctx.state == ClientTlsState.HANDSHAKE_COMPLETE
    assert client_result.traffic_secret == server_result.traffic_secret


def test_tls_client_cert_verification_fails_wrong_ca() -> None:
    """Certificate verification fails with wrong CA."""
    from cryptography.hazmat.primitives.serialization import Encoding

    from tests.utils import generate_ec_certificate

    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    # Generate a different CA cert that didn't sign the server cert
    wrong_ca_cert_obj, _ = generate_ec_certificate("wrong-ca.test")
    wrong_ca_pem = wrong_ca_cert_obj.public_bytes(Encoding.PEM)
    client_ctx = QuicClientTlsContext(ca_certs=wrong_ca_pem, verify_mode=True)

    client_hello = client_ctx.build_client_hello()
    server_result = server_ctx.receive(client_hello)

    sh_end = _find_message_end(server_result.data_to_send, 0)
    client_ctx.receive(server_result.data_to_send[:sh_end])
    with pytest.raises(ValueError, match="certificate verification failed"):
        client_ctx.receive(server_result.data_to_send[sh_end:])


def test_tls_client_finished_verifiable_by_server() -> None:
    """Client's Finished message passes server verification."""
    server_ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    client_ctx = QuicClientTlsContext(verify_mode=False)

    client_hello = client_ctx.build_client_hello()
    server_result = server_ctx.receive(client_hello)

    sh_end = _find_message_end(server_result.data_to_send, 0)
    client_ctx.receive(server_result.data_to_send[:sh_end])
    client_result = client_ctx.receive(server_result.data_to_send[sh_end:])

    # Feed client Finished back to server — should not raise
    final_result = server_ctx.receive(client_result.data_to_send)
    assert final_result.state == TlsHandshakeState.HANDSHAKE_COMPLETE


# --- Helpers ---


def _find_message_end(data: bytes, offset: int) -> int:
    """Find the end of a TLS handshake message at offset."""
    if offset + 4 > len(data):
        raise ValueError("Truncated message")
    msg_len = int.from_bytes(data[offset + 1 : offset + 4], "big")
    return offset + 4 + msg_len
