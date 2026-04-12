"""Connection migration detection and path validation tests (RFC 9000 §9)."""

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import ConnectionMigrated

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
ADDR = ("127.0.0.1", 4433)
NEW_ADDR = ("10.0.0.2", 5555)


def _make_client_server() -> tuple[QuicConnection, QuicConnection]:
    server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
    client_config = QuicConfiguration(is_client=True, verify_mode=False)
    return QuicConnection(client_config), QuicConnection(server_config)


def _transfer(
    sender: QuicConnection, receiver: QuicConnection, addr: tuple[str, int] = ADDR
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


class TestMigrationDetection:
    def test_same_addr_no_migration(self) -> None:
        """Packets from the same address don't trigger migration."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Client sends data from same address
        client.send_stream_data(0, b"hello", end_stream=True)
        events = _transfer(client, server)
        # No migration event — address unchanged
        assert not any(isinstance(e, ConnectionMigrated) for e in events)

    def test_new_addr_triggers_path_challenge(self) -> None:
        """Packet from new address causes server to send PATH_CHALLENGE."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Client sends data, but we deliver it from a new address
        client.send_stream_data(0, b"hello", end_stream=True)
        datagrams = client.send_datagrams()

        # Feed to server from new address
        events = []
        for dg in datagrams:
            events.extend(server.datagram_received(dg, NEW_ADDR))

        # Server should have queued a PATH_CHALLENGE response packet
        server_datagrams = server.send_datagrams()
        assert len(server_datagrams) >= 1, "Server should send PATH_CHALLENGE to new addr"

        # Server's _peer_addr should NOT have changed yet (pending validation)
        assert server._peer_addr == ADDR, "peer_addr should not change before validation"
        assert server._migrating_addr == NEW_ADDR

    def test_migration_completes_on_path_response(self) -> None:
        """Full migration: new addr → PATH_CHALLENGE → PATH_RESPONSE → ConnectionMigrated."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Client sends data from new address
        client.send_stream_data(0, b"hello", end_stream=True)
        datagrams = client.send_datagrams()
        for dg in datagrams:
            server.datagram_received(dg, NEW_ADDR)

        # Server sends PATH_CHALLENGE (and maybe other packets)
        server_datagrams = server.send_datagrams()

        # Client receives PATH_CHALLENGE, echoes PATH_RESPONSE
        client_events = []
        for dg in server_datagrams:
            client_events.extend(client.datagram_received(dg, ADDR))

        # Client sends PATH_RESPONSE back
        client_datagrams = client.send_datagrams()

        # Server receives PATH_RESPONSE from new addr → migration completes
        server_events = []
        for dg in client_datagrams:
            server_events.extend(server.datagram_received(dg, NEW_ADDR))

        migration_events = [e for e in server_events if isinstance(e, ConnectionMigrated)]
        assert len(migration_events) == 1
        assert migration_events[0].old_addr == ADDR
        assert migration_events[0].new_addr == NEW_ADDR
        assert server._peer_addr == NEW_ADDR

    def test_disable_active_migration_blocks_migration(self) -> None:
        """If peer advertised disable_active_migration, address changes are ignored."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Simulate peer having advertised disable_active_migration
        server._peer_disable_active_migration = True

        # Client sends data from new address
        client.send_stream_data(0, b"hello", end_stream=True)
        datagrams = client.send_datagrams()
        for dg in datagrams:
            server.datagram_received(dg, NEW_ADDR)

        # Server should NOT have started migration
        assert server._peer_addr == ADDR
        assert server._migrating_addr is None
        assert server._pending_path_challenge is None

    def test_handshake_addr_changes_accepted_unconditionally(self) -> None:
        """During handshake, address changes are accepted without validation."""
        client, server = _make_client_server()
        client.connect()

        # First exchange from original address
        _transfer(client, server)

        # Server responds from different address — client in HANDSHAKE, accepts
        server_datagrams = server.send_datagrams()
        diff_addr = ("192.168.1.1", 9999)
        for dg in server_datagrams:
            client.datagram_received(dg, diff_addr)

        # Client should have updated peer_addr (handshake phase = unconditional)
        assert client._peer_addr == diff_addr

    def test_congestion_state_reset_on_migration(self) -> None:
        """Congestion controller and RTT estimator are reset on migration (RFC 9000 §9.4)."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Record pre-migration congestion state
        old_cc = server._cc
        old_rtt = server._rtt

        # Trigger migration + validation
        client.send_stream_data(0, b"hello", end_stream=True)
        for dg in client.send_datagrams():
            server.datagram_received(dg, NEW_ADDR)
        for dg in server.send_datagrams():
            client.datagram_received(dg, ADDR)
        for dg in client.send_datagrams():
            server.datagram_received(dg, NEW_ADDR)

        # Congestion state should be new instances (reset)
        assert server._cc is not old_cc
        assert server._rtt is not old_rtt
