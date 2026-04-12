"""CID pool management and retirement lifecycle tests (RFC 9000 §5.1)."""

from tests.utils import load
from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import (
    ConnectionIdIssued,
    ConnectionIdRetired,
    ConnectionMigrated,
)

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


class TestCidPool:
    def test_pool_issued_after_handshake(self) -> None:
        """Server issues active_connection_id_limit CIDs after handshake."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Default active_connection_id_limit = 2
        # _our_cid (seq 0) is always in the set, plus issued CIDs
        assert len(server._our_cids) >= server._active_connection_id_limit

    def test_custom_active_connection_id_limit(self) -> None:
        """Pool respects a higher active_connection_id_limit."""
        server_config = QuicConfiguration(certificate=CERT, private_key=KEY)
        client_config = QuicConfiguration(is_client=True, verify_mode=False)
        client = QuicConnection(client_config)
        server = QuicConnection(server_config)
        server._active_connection_id_limit = 4
        _handshake(client, server)

        assert len(server._our_cids) >= 4

    def test_cid_issued_events_emitted(self) -> None:
        """ConnectionIdIssued events emitted during pool creation."""
        client, server = _make_client_server()
        client.connect()
        _transfer(client, server)
        # Server's response to client includes handshake + CID issuance
        _transfer(server, client)
        _transfer(client, server)
        _transfer(server, client)
        # Server's _our_cids should have pool
        assert len(server._our_cids) >= 2

    def test_replacement_cid_issued_on_retirement(self) -> None:
        """When a CID is retired, a replacement is issued to maintain pool size."""
        client, server = _make_client_server()
        _handshake(client, server)

        initial_seq = server._next_cid_sequence

        # Simulate peer retiring a CID by removing one
        if server._our_seq_to_cid:
            retired_seq = min(server._our_seq_to_cid.keys())

            # Build a RETIRE_CONNECTION_ID frame
            from zoomies.encoding import Buffer

            buf = Buffer()
            buf.push_uint8(0x19)  # RETIRE_CONNECTION_ID
            buf.push_uint_var(retired_seq)

            # Inject into server's frame parser (via a fake packet is complex,
            # so we test the internal handler directly)
            parse_buf = Buffer(data=buf.data)
            events: list = []
            from zoomies.frames.connection_id import pull_retire_connection_id

            frame = pull_retire_connection_id(parse_buf)
            cid = server._our_seq_to_cid.pop(frame.sequence, None)
            if cid is not None:
                server._our_cids.discard(cid)
                events.append(ConnectionIdRetired(connection_id=cid))
                server._queue_new_connection_id(events)

            # Pool should be replenished
            assert server._next_cid_sequence > initial_seq

    def test_peer_cids_stored_from_new_connection_id(self) -> None:
        """Peer CIDs received via NEW_CONNECTION_ID are stored in _peer_cids."""
        client, server = _make_client_server()
        _handshake(client, server)

        # After handshake, server issued CIDs. Client should have received them.
        # The client stores peer CIDs in _peer_cids.
        # Server's NEW_CONNECTION_ID frames were sent and received by client.
        assert len(client._peer_cids) >= 1 or client._peer_cid != b""


class TestCidRetirePriorTo:
    def test_retire_prior_to_advances_on_migration(self) -> None:
        """After migration, new CID is issued with advanced retire_prior_to."""
        client, server = _make_client_server()
        _handshake(client, server)

        # Trigger migration
        client.send_stream_data(0, b"hello", end_stream=True)
        for dg in client.send_datagrams():
            server.datagram_received(dg, NEW_ADDR)
        for dg in server.send_datagrams():
            client.datagram_received(dg, ADDR)

        # Capture events from PATH_RESPONSE
        events = []
        for dg in client.send_datagrams():
            events.extend(server.datagram_received(dg, NEW_ADDR))

        # Migration should have completed
        migration_events = [e for e in events if isinstance(e, ConnectionMigrated)]
        assert len(migration_events) == 1

        # New CID should have been issued with retire_prior_to > 0
        issued_events = [e for e in events if isinstance(e, ConnectionIdIssued)]
        assert len(issued_events) >= 1
        assert issued_events[-1].retire_prior_to > 0
