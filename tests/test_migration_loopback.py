"""End-to-end loopback migration integration tests.

Two QuicConnection instances (client + server) perform a full handshake,
exchange data, then simulate migration scenarios.
"""

import pytest

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import (
    ConnectionIdIssued,
    ConnectionMigrated,
    StreamDataReceived,
)

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)
NEW_ADDR = ("10.0.0.2", 5555)
NAT_ADDR = ("192.168.1.100", 12345)


def _make_client_server() -> tuple[QuicConnection, QuicConnection]:
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    return QuicConnection(client_config), QuicConnection(server_config)


def _transfer(
    sender: QuicConnection,
    receiver: QuicConnection,
    addr: tuple[str, int] = ADDR,
) -> list:
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, addr))
    return events


def _handshake(client: QuicConnection, server: QuicConnection) -> None:
    client.connect()
    _transfer(client, server)
    _transfer(server, client)
    _transfer(client, server)
    _transfer(server, client)


@pytest.mark.integration
class TestLoopbackMigration:
    """Full client→server migration over loopback."""

    def test_handshake_then_migrate_then_data(self) -> None:
        """Full flow: handshake → data → migrate → data on new path."""
        client, server = _make_client_server()
        _handshake(client, server)

        # 1. Pre-migration data exchange
        client.send_stream_data(0, b"pre-migration", end_stream=False)
        server_events = _transfer(client, server)
        stream_data = [e for e in server_events if isinstance(e, StreamDataReceived)]
        assert len(stream_data) >= 1
        assert stream_data[0].data == b"pre-migration"

        # 2. Client "migrates" — sends next packet from new address
        client.send_stream_data(0, b"post-migration", end_stream=True)
        datagrams = client.send_datagrams()
        all_events = []
        for dg in datagrams:
            all_events.extend(server.datagram_received(dg, NEW_ADDR))

        # Server detected address change, sent PATH_CHALLENGE
        assert server._migrating_addr == NEW_ADDR
        assert server._pending_path_challenge is not None

        # 3. PATH_CHALLENGE → client → PATH_RESPONSE → server (validates new path)
        client_events = _transfer(server, client, ADDR)
        server_events = _transfer(client, server, NEW_ADDR)

        migration_events = [e for e in server_events if isinstance(e, ConnectionMigrated)]
        assert len(migration_events) == 1
        assert migration_events[0].old_addr == ADDR
        assert migration_events[0].new_addr == NEW_ADDR
        assert server._peer_addr == NEW_ADDR

        # 4. Data continues flowing on new path
        server.send_stream_data(0, b"reply on new path", end_stream=True)
        client_events = _transfer(server, client, NEW_ADDR)
        stream_data = [e for e in client_events if isinstance(e, StreamDataReceived)]
        assert len(stream_data) >= 1
        assert stream_data[0].data == b"reply on new path"

    def test_nat_rebinding_validated(self) -> None:
        """NAT rebinding: same CID, different source address → PATH_CHALLENGE validates."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Client sends from NAT-rebound address
        client.send_stream_data(0, b"nat-rebound", end_stream=True)
        for dg in client.send_datagrams():
            server.datagram_received(dg, NAT_ADDR)

        # Server sends PATH_CHALLENGE
        assert server._migrating_addr == NAT_ADDR
        assert server._pending_path_challenge is not None

        # Client receives challenge and responds
        _transfer(server, client, ADDR)
        server_events = _transfer(client, server, NAT_ADDR)

        # Migration completes
        migration_events = [e for e in server_events if isinstance(e, ConnectionMigrated)]
        assert len(migration_events) == 1
        assert migration_events[0].new_addr == NAT_ADDR
        assert server._peer_addr == NAT_ADDR


@pytest.mark.integration
class TestLoopbackCidRotation:
    """CID pool maintenance and rotation over loopback."""

    def test_cid_pool_maintained_after_handshake(self) -> None:
        """Server maintains CID pool at active_connection_id_limit after handshake."""
        client, server = _make_client_server()
        _handshake(client, server)

        assert len(server._our_cids) >= server._active_connection_id_limit
        # All CIDs should be unique
        assert len(server._our_cids) == len(set(server._our_cids))

    def test_retire_prior_to_advances_on_migration(self) -> None:
        """After migration, server issues CID with advanced retire_prior_to."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Trigger full migration
        client.send_stream_data(0, b"migrate", end_stream=True)
        for dg in client.send_datagrams():
            server.datagram_received(dg, NEW_ADDR)
        _transfer(server, client, ADDR)
        events = _transfer(client, server, NEW_ADDR)

        # Check that a new CID was issued with retire_prior_to > 0
        issued = [e for e in events if isinstance(e, ConnectionIdIssued)]
        assert any(e.retire_prior_to > 0 for e in issued)

    def test_multiple_migrations_rotate_cids(self) -> None:
        """Multiple migrations cause CID rotation with increasing retire_prior_to."""
        client, server = _make_client_server()
        _handshake(client, server)

        addrs = [
            ("10.0.0.1", 6001),
            ("10.0.0.2", 6002),
            ("10.0.0.3", 6003),
        ]

        max_retire = 0
        for i, addr in enumerate(addrs):
            client.send_stream_data(0, f"migration-{i}".encode(), end_stream=(i == len(addrs) - 1))
            for dg in client.send_datagrams():
                server.datagram_received(dg, addr)
            _transfer(server, client, ADDR)
            events = _transfer(client, server, addr)

            issued = [e for e in events if isinstance(e, ConnectionIdIssued)]
            for e in issued:
                max_retire = max(max_retire, e.retire_prior_to)

        # retire_prior_to should have advanced across migrations
        assert max_retire > 0
        assert server._peer_addr == addrs[-1]


@pytest.mark.integration
class TestDisableActiveMigration:
    """Verify disable_active_migration transport parameter enforcement."""

    def test_migration_blocked_when_disabled(self) -> None:
        """Server ignores address changes when peer advertised disable_active_migration."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Peer advertised disable_active_migration
        server._peer_disable_active_migration = True

        client.send_stream_data(0, b"from-new-addr", end_stream=True)
        for dg in client.send_datagrams():
            server.datagram_received(dg, NEW_ADDR)

        # Server should not have initiated migration
        assert server._peer_addr == ADDR
        assert server._migrating_addr is None
        assert server._pending_path_challenge is None

        # Data should still be processed (packet is valid, just addr is ignored)
        # No PATH_CHALLENGE sent
        server.send_datagrams()  # drain queue (may have ACKs but no PATH_CHALLENGE)
