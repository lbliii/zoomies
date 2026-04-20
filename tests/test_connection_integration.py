"""End-to-end integration test — full client↔server lifecycle in one process.

This test is the reference spec for what a correct caller loop looks like.
It drives the full QUIC lifecycle — ``connect() → HandshakeComplete →
stream exchange → close`` — using two in-process ``QuicConnection``
instances and a deterministic monotonic clock.

If this test fails, the library is broken. Copy the shape of
``_transfer`` + ``_handshake`` for your own transport.
"""

import pytest

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import (
    ConnectionClosed,
    HandshakeComplete,
    QuicEvent,
    StreamDataReceived,
)

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)


class _Clock:
    """Deterministic monotonic clock for tests — never goes backwards."""

    def __init__(self, start: float = 1.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def tick(self, dt: float = 0.01) -> float:
        self._t += dt
        return self._t


def _transfer(sender: QuicConnection, receiver: QuicConnection, clock: _Clock) -> list[QuicEvent]:
    """Shuttle every datagram sender produced into receiver; return events."""
    events: list[QuicEvent] = []
    for dg in sender.send_datagrams(now=clock.now()):
        clock.tick()
        events.extend(receiver.datagram_received(dg, ADDR, now=clock.now()))
    return events


@pytest.mark.integration
def test_full_lifecycle() -> None:
    """Golden path: handshake → stream echo → clean close.

    Asserts the three events every caller must learn to pattern-match on:
    ``HandshakeComplete``, ``StreamDataReceived``, ``ConnectionClosed`` —
    in that order, with the exact data the peer sent.
    """
    clock = _Clock(start=1.0)
    server = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False, server_name="localhost")
    )

    # --- Handshake ---------------------------------------------------------
    client.connect()

    # Initial → server (ClientHello)
    _transfer(client, server, clock)
    # Initial + Handshake + 1-RTT → client (ServerHello, EE, Cert, Fin, HANDSHAKE_DONE)
    client_events = _transfer(server, client, clock)
    # Handshake + ACKs → server (client Finished)
    _transfer(client, server, clock)
    # ACKs → client
    _transfer(server, client, clock)

    handshake = [e for e in client_events if isinstance(e, HandshakeComplete)]
    assert len(handshake) == 1, "client must observe HandshakeComplete"

    # --- Bidirectional stream exchange ------------------------------------
    client.send_stream_data(0, b"ping", end_stream=True)
    server_events = _transfer(client, server, clock)
    received_on_server = [
        e for e in server_events if isinstance(e, StreamDataReceived) and e.stream_id == 0
    ]
    assert len(received_on_server) == 1
    assert received_on_server[0].data == b"ping"
    assert received_on_server[0].end_stream is True
    assert received_on_server[0].is_0rtt is False

    server.send_stream_data(0, b"pong", end_stream=True)
    client_events = _transfer(server, client, clock)
    received_on_client = [
        e for e in client_events if isinstance(e, StreamDataReceived) and e.stream_id == 0
    ]
    assert len(received_on_client) == 1
    assert received_on_client[0].data == b"pong"
    assert received_on_client[0].end_stream is True

    # --- Clean close -------------------------------------------------------
    client.close(error_code=0, reason="done")
    server_events = _transfer(client, server, clock)
    close = [e for e in server_events if isinstance(e, ConnectionClosed)]
    assert len(close) == 1
    assert close[0].error_code == 0
    assert close[0].reason == "done"


@pytest.mark.integration
def test_timer_loop_is_quiescent_after_close() -> None:
    """After a clean close, ``get_timer`` returns None — no pending deadlines.

    Callers that don't respect this will spin in a hot loop forever.
    """
    clock = _Clock(start=1.0)
    server = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False, server_name="localhost")
    )

    client.connect()
    _transfer(client, server, clock)
    _transfer(server, client, clock)
    _transfer(client, server, clock)
    _transfer(server, client, clock)

    client.close(error_code=0, reason="done")
    _transfer(client, server, clock)

    assert client.get_timer() is None
    assert server.get_timer() is None
