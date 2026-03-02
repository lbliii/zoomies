"""TLS handshake state machine (basic)."""

import pytest

from tests.utils import load
from zoomies.crypto.tls import (
    QuicTlsContext,
    TlsHandshakeResult,
    TlsHandshakeState,
    _hkdf_expand_label,
    _hkdf_extract,
    _parse_client_hello,
    _push_block,
)
from zoomies.encoding.buffer import BufferReadError

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")


def test_tls_context_initial_state() -> None:
    """QuicTlsContext starts in START state."""
    ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    assert ctx.state == TlsHandshakeState.START


def test_tls_receive_empty() -> None:
    """Empty input returns current state, no data to send."""
    ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    result = ctx.receive(b"")
    assert result.state == TlsHandshakeState.START
    assert result.data_to_send == b""


def test_tls_receive_transitions_state() -> None:
    """Receiving data transitions from START to CLIENT_HELLO_RECEIVED."""
    ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    result = ctx.receive(b"\x16\x03\x01\x00\x00")  # placeholder TLS data
    assert result.state == TlsHandshakeState.CLIENT_HELLO_RECEIVED
    assert ctx.state == TlsHandshakeState.CLIENT_HELLO_RECEIVED


def test_tls_handshake_result_frozen() -> None:
    """TlsHandshakeResult is immutable."""
    r = TlsHandshakeResult(
        state=TlsHandshakeState.START,
        data_to_send=b"",
    )
    assert r.state == TlsHandshakeState.START
    assert r.data_to_send == b""
    assert r.handshake_secret is None
    assert r.traffic_secret is None


# --- TLS helper unit tests (Phase 3.1) ---


def test_hkdf_extract_rfc5869_vector() -> None:
    """_hkdf_extract matches RFC 5869 Test Case 1 (SHA-256)."""
    salt = bytes.fromhex("000102030405060708090a0b0c")
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    prk = _hkdf_extract(salt, ikm)
    expected = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    assert prk == expected


def test_hkdf_extract_deterministic() -> None:
    """_hkdf_extract returns 32 bytes, deterministic for same inputs."""
    salt = b"\x00" * 32
    ikm = b"\x01" * 32
    prk1 = _hkdf_extract(salt, ikm)
    prk2 = _hkdf_extract(salt, ikm)
    assert len(prk1) == 32
    assert prk1 == prk2


def test_hkdf_expand_label_output_length() -> None:
    """_hkdf_expand_label produces requested length."""
    secret = b"\x00" * 32
    out = _hkdf_expand_label(secret, b"test", b"context", 48)
    assert len(out) == 48


def test_parse_client_hello_wrong_type() -> None:
    """_parse_client_hello with wrong handshake type raises ValueError."""
    # 0x02 = ServerHello, not ClientHello
    data = bytes([0x02, 0x00, 0x00, 0x00])
    with pytest.raises(ValueError, match="Expected ClientHello"):
        _parse_client_hello(data)


def test_parse_client_hello_truncated() -> None:
    """_parse_client_hello with truncated payload raises."""
    # ClientHello type, length 3, but only 1 byte of payload (need version 2 bytes)
    data = bytes([0x01, 0x00, 0x00, 0x01, 0x03])  # len=1, payload 1 byte
    with pytest.raises((BufferReadError, ValueError)):
        _parse_client_hello(data)


def test_parse_client_hello_truncated_extensions() -> None:
    """_parse_client_hello with truncated extensions raises."""
    # Minimal: type 1, len, version 0x0303, random 32, session_id 0, ciphers 0, compression 0
    # extensions len 2, but only 1 byte (truncated)
    inner = (
        b"\x03\x03"  # version
        + b"\x00" * 32  # random
        + b"\x00"  # session_id len 0
        + b"\x00\x00"  # cipher suites len 0
        + b"\x00"  # compression len 0
        + b"\x00\x02\xab"  # extensions len 2, but only 1 byte (truncated)
    )
    data = bytes([0x01]) + len(inner).to_bytes(3, "big") + inner
    with pytest.raises((BufferReadError, ValueError)):
        _parse_client_hello(data)


def test_tls_client_hello_produces_server_hello() -> None:
    """QuicTlsContext.receive with valid ClientHello returns ServerHello in data_to_send."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from zoomies.encoding import Buffer

    # Build minimal valid ClientHello with X25519 key share
    priv = x25519.X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    inner = Buffer()
    inner.push_uint16(0x0303)  # legacy version
    inner.push_bytes(b"\x00" * 32)  # random
    _push_block(inner, 1, b"")  # session_id
    _push_block(inner, 2, bytes([0x13, 0x01]))  # TLS_AES_128_GCM_SHA256
    _push_block(inner, 1, bytes([0x00]))  # compression null
    key_share_payload = Buffer()
    share_data = Buffer()
    share_data.push_uint16(0x001D)  # X25519
    share_data.push_uint16(len(pub_bytes))
    share_data.push_bytes(pub_bytes)
    key_share_payload.push_uint16(len(share_data.data))  # client_shares length
    key_share_payload.push_bytes(share_data.data)
    ext_buf = Buffer()
    ext_buf.push_uint16(51)  # key_share
    ext_buf.push_uint16(len(key_share_payload.data))
    ext_buf.push_bytes(key_share_payload.data)
    _push_block(inner, 2, ext_buf.data)
    msg = bytes([0x01]) + len(inner.data).to_bytes(3, "big") + inner.data

    ctx = QuicTlsContext(certificate=CERT, private_key=KEY)
    result = ctx.receive(msg)
    assert result.state == TlsHandshakeState.CLIENT_HELLO_RECEIVED
    assert len(result.data_to_send) > 0
    assert result.data_to_send[:1] == bytes([0x02])  # ServerHello
