"""Phase 4 tests — congestion control, key update, STOP_SENDING/RESET_STREAM, variable PN."""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.core.connection import ConnectionState
from zoomies.crypto import CryptoPair
from zoomies.encoding import Buffer
from zoomies.events import StopSendingReceived, StreamReset
from zoomies.frames.stream import (
    ResetStreamFrame,
    StopSendingFrame,
    pull_reset_stream_frame,
    pull_stop_sending_frame,
    push_reset_stream_frame,
    push_stop_sending_frame,
)
from zoomies.primitives import StreamId
from zoomies.recovery import SentPingFrame
from zoomies.recovery.congestion import (
    INITIAL_WINDOW,
    MAX_DATAGRAM_SIZE,
    MINIMUM_WINDOW,
    CongestionController,
)
from zoomies.recovery.sent_packet import SentPacket

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"


def _make_server_conn() -> QuicConnection:
    """Create a server-side connection in ONE_RTT state for testing."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True
    return conn


# --- CongestionController unit tests ---


def test_cc_initial_state() -> None:
    """CongestionController starts with correct initial window."""
    cc = CongestionController()
    assert cc.congestion_window == INITIAL_WINDOW
    assert cc.bytes_in_flight == 0
    assert cc.can_send(1200)


def test_cc_on_packet_sent_tracks_bytes() -> None:
    """on_packet_sent increases bytes_in_flight."""
    cc = CongestionController()
    cc.on_packet_sent(1200)
    assert cc.bytes_in_flight == 1200
    cc.on_packet_sent(1200)
    assert cc.bytes_in_flight == 2400


def test_cc_can_send_false_when_full() -> None:
    """can_send returns False when window is exhausted."""
    cc = CongestionController()
    cc.on_packet_sent(INITIAL_WINDOW)
    assert not cc.can_send(1)


def test_cc_slow_start_growth() -> None:
    """In slow start, cwnd grows by acked bytes."""
    cc = CongestionController()
    # Send and ACK one packet
    cc.on_packet_sent(1200)
    pkt = SentPacket(
        packet_number=0,
        sent_time=1.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    cc.on_packets_acked([pkt])
    assert cc.congestion_window == INITIAL_WINDOW + 1200
    assert cc.bytes_in_flight == 0


def test_cc_congestion_avoidance_growth() -> None:
    """After loss, in congestion avoidance, cwnd grows linearly."""
    cc = CongestionController()
    # Trigger loss to set ssthresh
    cc.on_packet_sent(1200)
    lost_pkt = SentPacket(
        packet_number=0,
        sent_time=1.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    cc.on_packets_lost([lost_pkt], now=2.0)
    # Now ssthresh = cwnd (after halving)
    cwnd_after_loss = cc.congestion_window
    assert cwnd_after_loss == max(INITIAL_WINDOW // 2, MINIMUM_WINDOW)

    # Send and ACK a packet in congestion avoidance
    cc.on_packet_sent(1200)
    acked_pkt = SentPacket(
        packet_number=1,
        sent_time=2.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    cc.on_packets_acked([acked_pkt])
    # Linear growth: cwnd += MSS * sent_bytes / cwnd
    expected_growth = MAX_DATAGRAM_SIZE * 1200 // cwnd_after_loss
    assert cc.congestion_window == cwnd_after_loss + expected_growth


def test_cc_loss_halves_window() -> None:
    """On loss, cwnd is halved (min = MINIMUM_WINDOW)."""
    cc = CongestionController()
    cc.on_packet_sent(1200)
    lost_pkt = SentPacket(
        packet_number=0,
        sent_time=1.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    cc.on_packets_lost([lost_pkt], now=2.0)
    assert cc.congestion_window == max(INITIAL_WINDOW // 2, MINIMUM_WINDOW)
    assert cc.ssthresh == cc.congestion_window


def test_cc_minimum_window_floor() -> None:
    """cwnd never drops below MINIMUM_WINDOW."""
    cc = CongestionController()
    cc.congestion_window = MINIMUM_WINDOW
    cc.on_packet_sent(1200)
    lost_pkt = SentPacket(
        packet_number=0,
        sent_time=1.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    cc.on_packets_lost([lost_pkt], now=2.0)
    assert cc.congestion_window == MINIMUM_WINDOW


def test_cc_no_double_reduction_same_recovery() -> None:
    """Multiple losses in the same recovery period don't reduce cwnd again."""
    cc = CongestionController()
    cc.on_packet_sent(2400)
    pkt0 = SentPacket(
        packet_number=0,
        sent_time=1.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    pkt1 = SentPacket(
        packet_number=1,
        sent_time=1.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    cc.on_packets_lost([pkt0], now=2.0)
    cwnd_after_first = cc.congestion_window
    # Second loss in same recovery period (sent_time=1.0 <= recovery_start)
    cc.on_packets_lost([pkt1], now=2.0)
    assert cc.congestion_window == cwnd_after_first


# --- RESET_STREAM / STOP_SENDING frame tests ---


def test_reset_stream_frame_roundtrip() -> None:
    """RESET_STREAM frame serializes and parses correctly."""
    frame = ResetStreamFrame(stream_id=StreamId(4), error_code=0x01, final_size=1000)
    buf = Buffer()
    push_reset_stream_frame(buf, frame)
    parsed = pull_reset_stream_frame(Buffer(data=buf.data))
    assert parsed.stream_id == StreamId(4)
    assert parsed.error_code == 0x01
    assert parsed.final_size == 1000


def test_stop_sending_frame_roundtrip() -> None:
    """STOP_SENDING frame serializes and parses correctly."""
    frame = StopSendingFrame(stream_id=StreamId(8), error_code=0x02)
    buf = Buffer()
    push_stop_sending_frame(buf, frame)
    parsed = pull_stop_sending_frame(Buffer(data=buf.data))
    assert parsed.stream_id == StreamId(8)
    assert parsed.error_code == 0x02


def test_connection_handles_reset_stream() -> None:
    """Connection emits StreamReset event on receiving RESET_STREAM frame."""
    conn = _make_server_conn()

    # Build a payload containing a RESET_STREAM frame
    payload_buf = Buffer()
    push_reset_stream_frame(
        payload_buf,
        ResetStreamFrame(stream_id=StreamId(4), error_code=0x01, final_size=500),
    )
    events: list = []
    conn._parse_payload_frames(payload_buf.data, events)

    reset_events = [e for e in events if isinstance(e, StreamReset)]
    assert len(reset_events) == 1
    assert reset_events[0].stream_id == 4
    assert reset_events[0].error_code == 0x01
    assert reset_events[0].final_size == 500


def test_connection_handles_stop_sending() -> None:
    """Connection emits StopSendingReceived event on STOP_SENDING frame."""
    conn = _make_server_conn()

    payload_buf = Buffer()
    push_stop_sending_frame(
        payload_buf,
        StopSendingFrame(stream_id=StreamId(8), error_code=0x02),
    )
    events: list = []
    conn._parse_payload_frames(payload_buf.data, events)

    stop_events = [e for e in events if isinstance(e, StopSendingReceived)]
    assert len(stop_events) == 1
    assert stop_events[0].stream_id == 8
    assert stop_events[0].error_code == 0x02


# --- Key update tests ---


def test_key_update_rotates_keys() -> None:
    """CryptoPair.update_keys() derives new keys and flips key_phase."""
    crypto = CryptoPair()
    crypto.setup_initial(cid=SERVER_CID, is_client=False)
    # Set up 1-RTT keys (simulated with initial keys for testability)
    crypto.setup_1rtt(b"\x00" * 32, is_client=False)
    assert crypto.key_phase == 0

    # Save old key for comparison
    old_send_key = crypto._send._key

    crypto.update_keys()
    assert crypto.key_phase == 1
    assert crypto._send._key != old_send_key

    # Update again flips back
    crypto.update_keys()
    assert crypto.key_phase == 0


def test_key_update_encrypt_decrypt() -> None:
    """After key update, encrypt/decrypt still works."""
    # Server side
    server = CryptoPair()
    server.setup_1rtt(b"\xab" * 32, is_client=False)

    # Client side
    client = CryptoPair()
    client.setup_1rtt(b"\xab" * 32, is_client=True)

    # Encrypt with server, decrypt with client
    plain_header = b"\x40" + SERVER_CID
    plain_payload = b"hello before key update"
    pn = 0
    encrypted = server.encrypt_packet(plain_header, plain_payload, pn)
    _, decrypted, _ = client.decrypt_packet(encrypted, len(plain_header), pn)
    assert decrypted == plain_payload

    # Update both sides
    server.update_keys()
    client.update_keys()

    # Encrypt/decrypt after key update
    pn = 1
    encrypted2 = server.encrypt_packet(plain_header, b"hello after update", pn)
    _, decrypted2, _ = client.decrypt_packet(encrypted2, len(plain_header), pn)
    assert decrypted2 == b"hello after update"


# --- Variable PN length tests ---


def test_optimal_pn_length_no_ack() -> None:
    """Without any ACK, use full 4-byte PN."""
    conn = _make_server_conn()
    assert conn._optimal_pn_length() == 4


def test_optimal_pn_length_small_distance() -> None:
    """Small distance from largest_acked uses 1-byte PN."""
    conn = _make_server_conn()
    conn._application_space.largest_acked_packet = 10
    conn._one_rtt_pn = 11  # distance = 1
    assert conn._optimal_pn_length() == 1


def test_optimal_pn_length_medium_distance() -> None:
    """Medium distance uses 2-byte PN."""
    conn = _make_server_conn()
    conn._application_space.largest_acked_packet = 0
    conn._one_rtt_pn = 0x100  # distance = 256
    assert conn._optimal_pn_length() == 2


def test_optimal_pn_length_large_distance() -> None:
    """Large distance uses 4-byte PN."""
    conn = _make_server_conn()
    conn._application_space.largest_acked_packet = 0
    conn._one_rtt_pn = 0x10000  # distance = 65536
    assert conn._optimal_pn_length() == 4


# --- Congestion control integration ---


def test_congestion_window_gates_send() -> None:
    """When cwnd is exhausted, stream data is deferred."""
    conn = _make_server_conn()
    # Set a very small congestion window
    conn._cc.congestion_window = 1200
    conn._cc.bytes_in_flight = 1200  # already full

    conn.send_stream_data(stream_id=0, data=b"blocked", end_stream=False)
    conn.send_datagrams(now=10.0)

    # Data should be deferred in the queue
    assert len(conn._stream_send_queue) >= 1


def test_congestion_window_allows_send() -> None:
    """When cwnd has space, stream data is sent."""
    conn = _make_server_conn()
    # Ensure enough window
    conn._cc.congestion_window = INITIAL_WINDOW

    conn.send_stream_data(stream_id=0, data=b"allowed", end_stream=False)
    datagrams = conn.send_datagrams(now=10.0)

    assert len(datagrams) >= 1
    assert len(conn._stream_send_queue) == 0


def test_cc_bytes_in_flight_updated_on_send() -> None:
    """Sending packets increases cc.bytes_in_flight."""
    conn = _make_server_conn()
    assert conn._cc.bytes_in_flight == 0

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    assert conn._cc.bytes_in_flight > 0
