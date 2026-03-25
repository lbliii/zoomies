"""Recovery integration tests — packet drops, retransmission, PTO escalation.

These tests simulate realistic loss scenarios at the connection level,
verifying that lost data is retransmitted and PTO probes fire correctly.
"""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.core.connection import ConnectionState
from zoomies.crypto import CryptoPair
from zoomies.frames.ack import AckFrame

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"


def _make_server_conn() -> QuicConnection:
    """Server connection in ONE_RTT state."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY, idle_timeout=60.0)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True
    conn._last_activity = 10.0
    return conn


def test_single_packet_loss_retransmits_stream_data() -> None:
    """A single dropped packet's STREAM data is retransmitted after ACK gap."""
    conn = _make_server_conn()
    conn._now = 10.0
    conn._rtt.update(latest_rtt=0.050)

    # Send 4 separate packets
    for i in range(4):
        conn.send_stream_data(stream_id=0, data=f"msg{i}".encode(), end_stream=False)
        conn.send_datagrams(now=10.0 + i * 0.001)

    assert len(conn._application_space.sent_packets) == 4

    # ACK packets 1,2,3 but NOT 0 (simulating drop of packet 0)
    # gap from 3: pkt0 has gap=3 → declared lost
    ack = AckFrame(ranges=(range(1, 4),), delay=0)
    conn._now = 10.1
    conn._process_ack(ack)

    # Packet 0 should have been retransmitted
    assert len(conn._stream_send_queue) >= 1
    _sid, data, _fin = conn._stream_send_queue[0]
    assert data == b"msg0"


def test_multiple_packet_loss_retransmits_all() -> None:
    """Multiple lost packets each get their STREAM frames re-queued."""
    conn = _make_server_conn()
    conn._now = 10.0
    conn._rtt.update(latest_rtt=0.050)

    for i in range(6):
        conn.send_stream_data(stream_id=0, data=f"d{i}".encode(), end_stream=False)
        conn.send_datagrams(now=10.0)

    # ACK only packet 5 → packets 0,1,2 have gap ≥ 3
    ack = AckFrame(ranges=(range(5, 6),), delay=0)
    conn._now = 10.5
    conn._process_ack(ack)

    retransmitted = {data for _, data, _ in conn._stream_send_queue}
    assert b"d0" in retransmitted
    assert b"d1" in retransmitted
    assert b"d2" in retransmitted


def test_pto_probe_fires_on_total_ack_loss() -> None:
    """With no ACKs at all, PTO fires and sends a PING probe."""
    conn = _make_server_conn()

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    pto = conn._rtt.pto_duration()
    assert conn._pto_count == 0

    # No ACKs — PTO fires
    conn.handle_timer(now=10.0 + pto + 0.001)
    assert conn._pto_count == 1
    assert conn._probe_needed is True

    # Sending datagrams produces the probe
    datagrams = conn.send_datagrams(now=10.0 + pto + 0.001)
    assert len(datagrams) >= 1
    assert conn._probe_needed is False


def test_pto_escalation_exponential_backoff() -> None:
    """Successive PTO firings use exponential backoff."""
    conn = _make_server_conn()

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    pto = conn._rtt.pto_duration()

    # First PTO fires at ~10 + pto
    t1 = 10.0 + pto + 0.001
    conn.handle_timer(now=t1)
    assert conn._pto_count == 1
    conn.send_datagrams(now=t1)  # sends probe at t1

    # Second PTO: from probe sent at t1, with backoff 2^1
    t2 = t1 + pto * 2 + 0.001
    conn.handle_timer(now=t2)
    assert conn._pto_count == 2
    conn.send_datagrams(now=t2)

    # Third PTO: from probe sent at t2, with backoff 2^2
    t3 = t2 + pto * 4 + 0.001
    conn.handle_timer(now=t3)
    assert conn._pto_count == 3


def test_pto_resets_on_successful_ack() -> None:
    """After PTO fires, receiving an ACK with RTT sample resets pto_count."""
    conn = _make_server_conn()
    conn._now = 10.0

    # Send packets
    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    # Fire PTO once
    pto = conn._rtt.pto_duration()
    t1 = 10.0 + pto + 0.001
    conn.handle_timer(now=t1)
    conn.send_datagrams(now=t1)  # sends probe

    # Fire PTO again from probe
    t2 = t1 + pto * 2 + 0.001
    conn.handle_timer(now=t2)
    conn.send_datagrams(now=t2)
    assert conn._pto_count == 2

    # Now ACK arrives for the original packet
    ack = AckFrame(ranges=(range(1),), delay=0)
    conn._now = t2 + 0.001
    conn._process_ack(ack)

    assert conn._pto_count == 0


def test_congestion_window_reduces_on_loss() -> None:
    """Packet loss triggers congestion window reduction."""
    conn = _make_server_conn()
    conn._now = 10.0
    conn._rtt.update(latest_rtt=0.050)

    initial_cwnd = conn._cc.congestion_window

    # Send several packets
    for _i in range(5):
        conn.send_stream_data(stream_id=0, data=b"x" * 100, end_stream=False)
        conn.send_datagrams(now=10.0)

    # ACK only packet 4 to trigger loss of packets 0,1
    ack = AckFrame(ranges=(range(4, 5),), delay=0)
    conn._now = 10.5
    conn._process_ack(ack)

    # cwnd should have been reduced
    assert conn._cc.congestion_window < initial_cwnd


def test_retransmission_produces_valid_packets() -> None:
    """Retransmitted stream data can be successfully sent as new packets."""
    conn = _make_server_conn()
    conn._now = 10.0
    conn._rtt.update(latest_rtt=0.050)

    # Send 4 packets
    for i in range(4):
        conn.send_stream_data(stream_id=0, data=f"data{i}".encode(), end_stream=False)
        conn.send_datagrams(now=10.0)

    pn_before_retransmit = conn._one_rtt_pn

    # ACK packet 3 only → packet 0 lost (gap=3)
    ack = AckFrame(ranges=(range(3, 4),), delay=0)
    conn._now = 10.5
    conn._process_ack(ack)

    # Retransmitted data is in the stream queue
    assert len(conn._stream_send_queue) >= 1

    # Sending produces new encrypted packets with new PNs
    retransmit_datagrams = conn.send_datagrams(now=10.5)
    assert len(retransmit_datagrams) >= 1
    assert conn._one_rtt_pn > pn_before_retransmit


def test_idle_timeout_still_works_with_recovery() -> None:
    """Idle timeout closes connection even when recovery machinery is active."""
    conn = _make_server_conn()
    conn._config = QuicConfiguration(
        certificate=CERT, private_key=KEY, idle_timeout=5.0
    )
    conn._last_activity = 10.0

    conn.handle_timer(now=15.1)
    assert conn._state == ConnectionState.CLOSED


def test_bytes_in_flight_consistent_after_ack() -> None:
    """bytes_in_flight decreases correctly when packets are ACKed."""
    conn = _make_server_conn()
    conn._now = 10.0

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    bif_before = conn._cc.bytes_in_flight
    assert bif_before > 0

    # ACK the packet
    ack = AckFrame(ranges=(range(1),), delay=0)
    conn._now = 10.1
    conn._process_ack(ack)

    assert conn._cc.bytes_in_flight < bif_before
