"""Retry token handler protocol — caller-owned address validation.

Sans-I/O contract: the library asks; the caller generates and validates tokens.
The caller owns time, state (token stores), and cryptographic token schemes.
"""

from typing import Protocol


class RetryTokenHandler(Protocol):
    """Caller-provided Retry token generation and validation.

    Sans-I/O contract: the protocol layer asks; the caller decides.
    The caller owns state (token stores, clocks, crypto).

    Token format is entirely caller-defined. The library treats tokens
    as opaque bytes.
    """

    def generate_token(self, original_dcid: bytes, client_addr: tuple[str, int]) -> bytes:
        """Generate a Retry token for the given client.

        Args:
            original_dcid: The original destination CID from the client's first Initial.
            client_addr: The client's (host, port) address.

        Returns:
            Opaque token bytes to include in the Retry packet.
        """
        ...

    def validate_token(self, token: bytes, client_addr: tuple[str, int]) -> bytes | None:
        """Validate a Retry token from a client's second Initial.

        Args:
            token: The token from the client's Initial packet.
            client_addr: The client's (host, port) address.

        Returns:
            The original destination CID if the token is valid, or None if invalid.
        """
        ...
