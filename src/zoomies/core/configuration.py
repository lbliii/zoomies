"""QUIC configuration — certificate, key, limits, client/server mode."""

import warnings
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

    Server mode (default): requires ``certificate`` and ``private_key``.
    Client mode (``is_client=True``): certificate/private_key ignored.

    **Sans-I/O timer contract**: ``idle_timeout`` only takes effect if the
    caller polls ``QuicConnection.get_timer()`` and calls
    ``QuicConnection.handle_timer(now)`` when the deadline passes. Without
    this, idle connections are never closed.

    Attributes:
        is_client: True for client mode, False for server mode (default).
        certificate: PEM-encoded server certificate (required for servers).
        private_key: PEM-encoded private key (required for servers).
        ca_certs: PEM-encoded CA certificates for peer verification.
            Required when ``is_client=True`` and ``verify_mode=True``.
        verify_mode: Whether to verify the peer's certificate chain.
        server_name: SNI hostname for client connections.
        max_data: Connection-level flow control limit in bytes. Peers may not
            send more than this total across all streams. Pass ``0`` to disable
            (unlimited). Default: 1 MB.
        max_stream_data: Per-stream flow control limit in bytes. Pass ``0`` to
            disable (unlimited). Default: 1 MB.
        idle_timeout: Seconds before an idle connection is closed. Requires
            the caller to implement a timer loop using ``get_timer()`` and
            ``handle_timer()`` — the library never sleeps.
        max_send_queue_bytes: Maximum bytes buffered for sending before
            ``send_stream_data()`` raises ``BufferError``. Default: 16 MB.
        zero_rtt_policy: Server-side policy for accepting 0-RTT early data.
            Must implement the ``ZeroRttPolicy`` protocol. None (default)
            rejects all 0-RTT.
        session_ticket: Client-side session ticket for TLS 1.3 resumption
            and 0-RTT. Obtain from a ``NewSessionTicket`` event after a
            previous handshake, then pass here on reconnection.
        retry_token_handler: Server-side handler for Retry token generation
            and validation. None (default) disables address validation
            via Retry.
    """

    is_client: bool = False
    certificate: bytes = b""
    private_key: bytes = b""
    ca_certs: bytes | None = None
    verify_mode: bool = True
    server_name: str | None = None
    max_data: int = 1_048_576  # 1 MB connection-level flow control
    max_stream_data: int = 1_048_576  # 1 MB per-stream flow control
    idle_timeout: float = 30.0
    max_send_queue_bytes: int = 16 * 1024 * 1024  # 16 MB default
    zero_rtt_policy: ZeroRttPolicy | None = None
    session_ticket: SessionTicket | None = None
    retry_token_handler: RetryTokenHandler | None = None

    def __post_init__(self) -> None:
        if not self.is_client:
            if not self.certificate:
                raise ValueError(
                    "Server QuicConfiguration requires non-empty 'certificate'. "
                    "Pass certificate=<PEM bytes> in QuicConfiguration, "
                    "or set is_client=True for a client-mode config."
                )
            if not self.private_key:
                raise ValueError(
                    "Server QuicConfiguration requires non-empty 'private_key'. "
                    "Pass private_key=<PEM bytes> in QuicConfiguration, "
                    "or set is_client=True for a client-mode config."
                )
        if self.is_client and self.verify_mode and self.ca_certs is None:
            raise ValueError(
                "Client QuicConfiguration with verify_mode=True requires 'ca_certs'. "
                "Pass ca_certs=<PEM bytes> in QuicConfiguration, "
                "or set verify_mode=False explicitly to skip peer-cert validation."
            )
        if self.idle_timeout < 0:
            raise ValueError(
                f"idle_timeout must be non-negative, got {self.idle_timeout}. "
                f"Pass idle_timeout=<seconds ≥ 0> in QuicConfiguration; 0 disables the timer."
            )
        if self.max_data < 0:
            raise ValueError(
                f"max_data must be non-negative, got {self.max_data}. "
                f"Pass max_data=<bytes ≥ 0> in QuicConfiguration; "
                f"0 disables connection-level flow control."
            )
        if self.max_stream_data < 0:
            raise ValueError(
                f"max_stream_data must be non-negative, got {self.max_stream_data}. "
                f"Pass max_stream_data=<bytes ≥ 0> in QuicConfiguration; "
                f"0 disables per-stream flow control."
            )
        if self.max_data == 0:
            warnings.warn(
                "max_data=0 disables connection-level flow control — "
                "a misbehaving peer can send unlimited data",
                stacklevel=2,
            )
        if self.server_name is not None and self.server_name == "":
            raise ValueError(
                "server_name must be None or a non-empty string, got an empty string. "
                "Pass server_name=<hostname> for SNI, or server_name=None to disable SNI."
            )
