"""PacketProtector protocol — encrypt/decrypt QUIC packets."""

from typing import Protocol


class PacketProtector(Protocol):
    """Protocol for packet protection (encrypt/decrypt)."""

    def encrypt(
        self,
        plain_header: bytes,
        plain_payload: bytes,
        packet_number: int,
    ) -> bytes: ...
    def decrypt(
        self,
        packet: bytes,
        encrypted_offset: int,
        expected_packet_number: int,
    ) -> tuple[bytes, bytes, int]: ...
