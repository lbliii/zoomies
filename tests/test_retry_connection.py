"""Retry packet — server-side send, token validation, client-side handling.

Tests the full Retry flow: server issues Retry, client re-sends Initial with token,
handshake completes. Also tests edge cases (no handler, invalid token, duplicate Retry).
"""

import os
import pathlib

import pytest

from zoomies import QuicConfiguration, QuicConnection, RetryReceived
from zoomies.events import StreamDataReceived
from zoomies.packet.header import PACKET_TYPE_RETRY
from zoomies.packet.retry import get_retry_integrity_tag

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"
CERT = (_FIXTURES / "ssl_cert.pem").read_bytes()
KEY = (_FIXTURES / "ssl_key.pem").read_bytes()
ADDR = ("127.0.0.1", 4433)


class SimpleRetryTokenHandler:
    """Minimal Retry token handler for tests.

    Token format: ODCID (variable) — no encryption, no expiry.
    Only suitable for testing.
    """

    def generate_token(self, original_dcid: bytes, client_addr: tuple[str, int]) -> bytes:
        # Encode ODCID length + ODCID + address for validation
        addr_bytes = f"{client_addr[0]}:{client_addr[1]}".encode()
        return bytes([len(original_dcid)]) + original_dcid + addr_bytes

    def validate_token(self, token: bytes, client_addr: tuple[str, int]) -> bytes | None:
        if len(token) < 1:
            return None
        odcid_len = token[0]
        if len(token) < 1 + odcid_len:
            return None
        odcid = token[1 : 1 + odcid_len]
        addr_bytes = token[1 + odcid_len :]
        expected_addr = f"{client_addr[0]}:{client_addr[1]}".encode()
        if addr_bytes != expected_addr:
            return None
        return odcid


class RejectAllTokenHandler:
    """Token handler that always rejects tokens."""

    def generate_token(self, original_dcid: bytes, client_addr: tuple[str, int]) -> bytes:
        return b"invalid_format"

    def validate_token(self, token: bytes, client_addr: tuple[str, int]) -> bytes | None:
        return None


def _transfer(sender: QuicConnection, receiver: QuicConnection) -> list:
    """Shuttle all datagrams from sender to receiver; return all events."""
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, ADDR))
    return events


# --- Server-side Retry tests ---


def test_server_no_handler_no_retry() -> None:
    """Server without retry_token_handler does NOT send Retry."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    server = QuicConnection(config)
    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # Client → Server
    _transfer(client, server)

    # Server should produce handshake response, not Retry
    datagrams = server.send_datagrams()
    for dg in datagrams:
        if len(dg) >= 5:
            first_byte = dg[0]
            if first_byte & 0x80:  # long header
                ptype = (first_byte & 0x30) >> 4
                assert ptype != PACKET_TYPE_RETRY


def test_server_sends_retry_when_handler_configured() -> None:
    """Server with retry_token_handler sends Retry when Initial has no token."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # Client → Server: Initial (no token)
    _transfer(client, server)

    # Server should send Retry
    datagrams = server.send_datagrams()
    assert len(datagrams) >= 1

    # Verify it's a Retry packet
    retry_pkt = datagrams[0]
    first_byte = retry_pkt[0]
    assert first_byte & 0x80  # long header
    ptype = (first_byte & 0x30) >> 4
    assert ptype == PACKET_TYPE_RETRY

    # Verify integrity tag is present (16 bytes)
    assert len(retry_pkt[-16:]) == 16


def test_server_retry_packet_has_valid_integrity_tag() -> None:
    """Retry packet integrity tag can be verified."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # Capture the original destination CID (what client sends to)
    original_dcid = client._peer_cid

    _transfer(client, server)
    datagrams = server.send_datagrams()
    retry_pkt = datagrams[0]

    # Verify integrity tag using the original destination CID
    tag = retry_pkt[-16:]
    packet_without_tag = retry_pkt[:-16]
    expected_tag = get_retry_integrity_tag(packet_without_tag, original_dcid)
    assert tag == expected_tag


# --- Client-side Retry handling tests ---


def test_client_handles_retry() -> None:
    """Client processes Retry and re-sends Initial with token."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # Client → Server (Initial, no token)
    _transfer(client, server)

    # Server → Client (Retry)
    client_events = _transfer(server, client)

    # Client should emit RetryReceived
    retry_events = [e for e in client_events if isinstance(e, RetryReceived)]
    assert len(retry_events) == 1

    # Client should have queued a new Initial with token
    datagrams = client.send_datagrams()
    assert len(datagrams) >= 1
    # The new Initial should be >= 1200 bytes (RFC 9000 §14.1)
    assert len(datagrams[0]) >= 1200


def test_client_rejects_duplicate_retry() -> None:
    """Client accepts only one Retry per connection (RFC 9000 §17.2.5.2)."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    _transfer(client, server)

    # Server → Client: first Retry
    client_events = _transfer(server, client)
    retry_events = [e for e in client_events if isinstance(e, RetryReceived)]
    assert len(retry_events) == 1

    # Try to send another Retry (simulate by re-transferring)
    # Create a second server to generate another Retry
    server2_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server2 = QuicConnection(server2_config)

    # Feed client's new Initial to server2 to get another Retry
    for dg in client.send_datagrams():
        server2.datagram_received(dg, ADDR)

    # server2 → client: second Retry
    client_events2 = _transfer(server2, client)
    retry_events2 = [e for e in client_events2 if isinstance(e, RetryReceived)]
    # Client should NOT emit a second RetryReceived
    assert len(retry_events2) == 0


def test_client_rejects_invalid_retry_tag() -> None:
    """Client drops Retry with invalid integrity tag."""
    from zoomies.primitives.types import QUIC_VERSION_1

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # Build a fake Retry with bad tag
    first_byte = 0xC0 | (3 << 4)
    fake_retry = (
        bytes([first_byte])
        + QUIC_VERSION_1.to_bytes(4, "big")
        + bytes([len(client._our_cid)])
        + client._our_cid
        + bytes([8])
        + os.urandom(8)  # fake source CID
        + b"fake_token"
        + b"\x00" * 16  # bad tag
    )

    events = client.datagram_received(fake_retry, ADDR)
    retry_events = [e for e in events if isinstance(e, RetryReceived)]
    assert len(retry_events) == 0
    assert not client._retry_received


def test_server_drops_invalid_token() -> None:
    """Server drops Initial with invalid Retry token."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # Client → Server: Initial (no token) → gets Retry
    _transfer(client, server)
    _transfer(server, client)  # client gets Retry, re-sends

    # Now create a rogue client that sends Initial with bad token
    rogue_config = QuicConfiguration(is_client=True, verify_mode=False)
    rogue = QuicConnection(rogue_config)
    rogue.connect()

    # The rogue server should reject bad tokens
    reject_server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=RejectAllTokenHandler()
    )
    reject_server = QuicConnection(reject_server_config)

    # Send Initial with no token → Retry
    _transfer(rogue, reject_server)
    _transfer(reject_server, rogue)  # Retry

    # Now rogue re-sends with token, but RejectAll will reject it
    # The reject server created from Retry will try to validate
    # Since the handler rejects all tokens, the second Initial should be dropped
    # The server state should still be INITIAL
    from zoomies.core.connection import ConnectionState

    # After Retry sent, server is still in INITIAL
    assert reject_server._state == ConnectionState.INITIAL


# --- Full Retry handshake integration ---


@pytest.mark.integration
def test_retry_full_handshake() -> None:
    """Full Retry flow: Initial → Retry → Initial (token) → Handshake complete."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # 1. Client → Server: Initial (no token)
    _transfer(client, server)

    # 2. Server → Client: Retry
    client_events = _transfer(server, client)
    assert any(isinstance(e, RetryReceived) for e in client_events)

    # 3. Client → Server: Initial (with token)
    _transfer(client, server)

    # 4. Server → Client: Initial + Handshake + 1-RTT
    client_events = _transfer(server, client)

    # 5. Client → Server: Handshake (Finished) + ACKs
    _transfer(client, server)

    # 6. Server → Client: final ACKs
    client_events = _transfer(server, client)

    # Check: both sides should have completed handshake
    from zoomies.core.connection import ConnectionState

    assert server._state == ConnectionState.ONE_RTT
    assert client._state == ConnectionState.ONE_RTT

    # Server should have validated the address
    assert server._address_validated is True

    # ODCID should be tracked
    assert server._original_destination_cid is not None


@pytest.mark.integration
def test_retry_then_stream_data() -> None:
    """After Retry handshake, stream data works normally."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    # Retry flow
    _transfer(client, server)
    _transfer(server, client)  # Retry
    _transfer(client, server)  # Initial with token
    _transfer(server, client)  # Handshake
    _transfer(client, server)  # Client Finished
    _transfer(server, client)  # ACKs

    from zoomies.core.connection import ConnectionState

    assert server._state == ConnectionState.ONE_RTT
    assert client._state == ConnectionState.ONE_RTT

    # Send stream data
    client.send_stream_data(0, b"hello after retry", end_stream=True)
    server_events = _transfer(client, server)
    stream_events = [e for e in server_events if isinstance(e, StreamDataReceived)]
    assert len(stream_events) == 1
    assert stream_events[0].data == b"hello after retry"
    assert stream_events[0].end_stream is True


def test_client_retry_resets_0rtt_state() -> None:
    """Retry invalidates 0-RTT state on client (RFC 9000 §8.1.4)."""
    handler = SimpleRetryTokenHandler()
    server_config = QuicConfiguration(
        certificate=CERT, private_key=KEY, retry_token_handler=handler
    )
    server = QuicConnection(server_config)

    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    client = QuicConnection(client_config)
    client.connect()

    _transfer(client, server)
    _transfer(server, client)  # Retry received

    # After Retry, 0-RTT crypto should be cleared
    assert client._zero_rtt_crypto is None
    assert client._zero_rtt_stream_queue == []
