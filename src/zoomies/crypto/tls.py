"""TLS 1.3 handshake adapter for QUIC (server-only initially).

Minimal state machine for QUIC TLS integration. Full handshake via cryptography
will be expanded in Phase 8.
"""

from dataclasses import dataclass
from enum import StrEnum


class TlsHandshakeState(StrEnum):
    """TLS handshake state for QUIC server."""

    START = "start"
    CLIENT_HELLO_RECEIVED = "client_hello_received"
    HANDSHAKE_COMPLETE = "handshake_complete"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class TlsHandshakeResult:
    """Result of processing TLS handshake data."""

    state: TlsHandshakeState
    data_to_send: bytes
    handshake_secret: bytes | None = None
    traffic_secret: bytes | None = None


class QuicTlsContext:
    """TLS 1.3 context for QUIC server handshake.

    Server-only initially. Processes incoming TLS handshake messages and
    produces outgoing messages. Secrets are derived for packet protection.
    """

    def __init__(self, *, certificate: bytes, private_key: bytes) -> None:
        self._certificate = certificate
        self._private_key = private_key
        self._state: TlsHandshakeState = TlsHandshakeState.START

    @property
    def state(self) -> TlsHandshakeState:
        return self._state

    def receive(self, data: bytes) -> TlsHandshakeResult:
        """Process incoming TLS handshake data.

        Returns updated state and data to send. Full implementation deferred.
        """
        if not data:
            return TlsHandshakeResult(state=self._state, data_to_send=b"")
        # Placeholder: transition to CLIENT_HELLO_RECEIVED on any data
        if self._state == TlsHandshakeState.START:
            self._state = TlsHandshakeState.CLIENT_HELLO_RECEIVED
        return TlsHandshakeResult(state=self._state, data_to_send=b"")
