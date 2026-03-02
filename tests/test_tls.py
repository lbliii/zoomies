"""TLS handshake state machine (basic)."""

from tests.utils import load
from zoomies.crypto.tls import (
    QuicTlsContext,
    TlsHandshakeResult,
    TlsHandshakeState,
)

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
