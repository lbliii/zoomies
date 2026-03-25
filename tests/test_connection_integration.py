"""Integration tests — full handshake with pre-recorded or loopback datagrams."""

import pytest

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")


@pytest.mark.integration
def test_connection_integration_placeholder() -> None:
    """Placeholder for full handshake integration test.

    TODO: Use pre-recorded aioquic client Initial or loopback datagrams
    to verify full handshake completion (HandshakeComplete when 1-RTT ready).
    """
    from zoomies.events import DecryptionFailed

    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    # Minimal Initial packet (unencrypted payload — decrypt will fail)
    pkt = bytes.fromhex("c300000001088394c8f03e51570808f067a5502a4262b500003200") + b"\x00" * 50
    events = conn.datagram_received(pkt, ("127.0.0.1", 443))
    datagrams = conn.send_datagrams()
    # Unencrypted packet fails decrypt — no response (correct: no amplification)
    assert datagrams == []
    assert any(isinstance(e, DecryptionFailed) for e in events)
