"""QUIC server configuration — certificate, key, limits."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class QuicConfiguration:
    """Server configuration for QUIC connection."""

    certificate: bytes
    private_key: bytes
    max_data: int = 0
    max_stream_data: int = 0
    idle_timeout: float = 30.0
