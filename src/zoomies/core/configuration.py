"""QUIC configuration — certificate, key, limits, client/server mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from zoomies.contracts.retry import RetryTokenHandler
    from zoomies.crypto.tls import SessionTicket


class ZeroRttPolicy(Protocol):
    """Caller-provided 0-RTT replay policy.

    Sans-I/O contract: the protocol layer asks; the caller decides.
    The caller owns state (ticket stores), clocks, and I/O.
    """

    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        """Return True to accept 0-RTT data for this ticket.

        Args:
            ticket_data: Opaque ticket bytes from the client's ClientHello.
            obfuscated_age: Client-reported ticket age (obfuscated per RFC 8446).

        Returns:
            True to accept and decrypt 0-RTT data.
            False to reject (client will resend as 1-RTT).
        """
        ...


@dataclass(frozen=True, slots=True)
class QuicConfiguration:
    """Configuration for QUIC connection (client or server).

    Server mode (default): requires certificate and private_key.
    Client mode (is_client=True): certificate/private_key ignored.
    """

    is_client: bool = False
    certificate: bytes = b""
    private_key: bytes = b""
    ca_certs: bytes | None = None
    verify_mode: bool = True
    server_name: str | None = None
    max_data: int = 0
    max_stream_data: int = 0
    idle_timeout: float = 30.0
    zero_rtt_policy: ZeroRttPolicy | None = None
    session_ticket: SessionTicket | None = None
    retry_token_handler: RetryTokenHandler | None = None
