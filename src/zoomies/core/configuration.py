"""QUIC configuration — certificate, key, limits, client/server mode."""

from dataclasses import dataclass


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
