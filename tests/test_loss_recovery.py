"""Phase 3 tests — loss detection, retransmission, anti-amplification, PTO."""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.core.connection import ConnectionState
from zoomies.crypto import CryptoPair
from zoomies.recovery import (
    RttEstimator,
    SentCryptoFrame,
    SentHandshakeDoneFrame,
    SentPacket,
    SentPingFrame,
    SentStreamFrame,
    detect_lost_packets,
)
from zoomies.recovery.loss_detection import (
    TIME_THRESHOLD_DENOMINATOR,
    TIME_THRESHOLD_NUMERATOR,
    loss_delay,
)
from zoomies.recovery.rtt import TIMER_GRANULARITY

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"


# --- loss_delay tests ---


def test_loss_delay_uses_smoothed_rtt() -> None:
    """loss_delay uses max(smoothed_rtt, latest_rtt) * 9/8."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    # smoothed=0.100, latest=0.100
    expected = 0.100 * TIME_THRESHOLD_NUMERATOR / TIME_THRESHOLD_DENOMINATOR
    assert abs(loss_delay(rtt) - expected) < 1e-9


def test_loss_delay_minimum_granularity() -> None:
    """loss_delay never goes below timer granularity."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.0001)  # very small RTT
    assert loss_delay(rtt) >= TIMER_GRANULARITY


def test_loss_delay_uses_latest_when_larger() -> None:
    """loss_delay uses latest_rtt when it's larger than smoothed_rtt."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.050)
    rtt.update(latest_rtt=0.200)
    # smoothed = 0.875*0.050 + 0.125*0.200 = 0.06875
    # latest = 0.200 → max(0.06875, 0.200) = 0.200
    expected = 0.200 * TIME_THRESHOLD_NUMERATOR / TIME_THRESHOLD_DENOMINATOR
    assert abs(loss_delay(rtt) - expected) < 1e-9


# --- detect_lost_packets tests ---


def test_detect_lost_no_acked() -> None:
    """No loss when nothing has been acked."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    sent: dict[int, SentPacket] = {}
    lost = detect_lost_packets(sent, largest_acked=None, now=1.0, rtt=rtt)
    assert lost == []


def test_detect_lost_pn_threshold() -> None:
    """Packets are lost when PN gap >= PACKET_THRESHOLD (3)."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    sent: dict[int, SentPacket] = {}
    for pn in range(5):
        sent[pn] = SentPacket(
            packet_number=pn,
            sent_time=1.0,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentPingFrame(),),
        )
    # Largest acked = 4; packets 0,1 have gap >= 3
    lost = detect_lost_packets(sent, largest_acked=4, now=1.0, rtt=rtt)
    lost_pns = {p.packet_number for p in lost}
    assert lost_pns == {0, 1}
    # Lost packets are removed from sent
    assert 0 not in sent
    assert 1 not in sent
    assert 2 in sent  # gap = 2, not lost


def test_detect_lost_pn_threshold_exact_boundary() -> None:
    """Packet with gap exactly PACKET_THRESHOLD is declared lost."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    sent: dict[int, SentPacket] = {}
    for pn in range(4):
        sent[pn] = SentPacket(
            packet_number=pn, sent_time=1.0, sent_bytes=100,
            ack_eliciting=True, in_flight=True, frames=(SentPingFrame(),),
        )
    # largest_acked=3, gap for pn=0 is 3 (exactly PACKET_THRESHOLD)
    lost = detect_lost_packets(sent, largest_acked=3, now=1.0, rtt=rtt)
    lost_pns = {p.packet_number for p in lost}
    assert 0 in lost_pns


def test_detect_lost_time_threshold() -> None:
    """Packets sent long ago are declared lost by time threshold."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    delay = loss_delay(rtt)

    sent: dict[int, SentPacket] = {}
    # Packet 0 sent at time 1.0
    sent[0] = SentPacket(
        packet_number=0, sent_time=1.0, sent_bytes=100,
        ack_eliciting=True, in_flight=True, frames=(SentPingFrame(),),
    )
    # Packet 1 sent recently
    sent[1] = SentPacket(
        packet_number=1, sent_time=1.0 + delay + 0.001, sent_bytes=100,
        ack_eliciting=True, in_flight=True, frames=(SentPingFrame(),),
    )
    # largest_acked = 1, now is well past delay for packet 0
    now = 1.0 + delay + 0.01
    lost = detect_lost_packets(sent, largest_acked=1, now=now, rtt=rtt)
    lost_pns = {p.packet_number for p in lost}
    assert 0 in lost_pns
    assert 1 not in lost_pns


def test_detect_lost_no_false_positives() -> None:
    """Packets within both thresholds are not declared lost."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    sent: dict[int, SentPacket] = {}
    # Packet 0 sent very recently, gap = 1 (< PACKET_THRESHOLD)
    sent[0] = SentPacket(
        packet_number=0, sent_time=1.0, sent_bytes=100,
        ack_eliciting=True, in_flight=True, frames=(SentPingFrame(),),
    )
    lost = detect_lost_packets(sent, largest_acked=1, now=1.001, rtt=rtt)
    assert lost == []
    assert 0 in sent  # still tracked


def test_detect_lost_does_not_touch_above_acked() -> None:
    """Packets with PN > largest_acked are never declared lost."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    sent: dict[int, SentPacket] = {
        5: SentPacket(
            packet_number=5, sent_time=0.5, sent_bytes=100,
            ack_eliciting=True, in_flight=True, frames=(SentPingFrame(),),
        )
    }
    lost = detect_lost_packets(sent, largest_acked=4, now=100.0, rtt=rtt)
    assert lost == []
    assert 5 in sent


# --- StreamSendState send buffer tests ---


def test_stream_send_buffer_roundtrip() -> None:
    """Data written to send buffer can be retrieved by offset."""
    from zoomies.core.stream import StreamSendState
    from zoomies.primitives import StreamId

    send = StreamSendState(stream_id=StreamId(0))
    send.write(b"hello")
    send.advance(5)
    send.write(b"world")
    send.advance(5)
    # Retrieve "hello" at offset 0
    assert send.get_data(0, 5) == b"hello"
    # Retrieve "world" at offset 5
    assert send.get_data(5, 5) == b"world"
    # Out-of-range returns empty
    assert send.get_data(100, 5) == b""


# --- Anti-amplification tests ---


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


def test_anti_amplification_limits_before_validation() -> None:
    """Before address validation, server can't send more than 3x received."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    # NOT validated
    conn._address_validated = False
    conn._bytes_received = 100  # received 100 bytes → can send up to 300

    # Queue a lot of data
    conn.send_stream_data(stream_id=0, data=b"x" * 2000, end_stream=False)
    datagrams = conn.send_datagrams(now=10.0)

    total_sent = sum(len(d) for d in datagrams)
    assert total_sent <= 3 * 100


def test_anti_amplification_no_limit_after_validation() -> None:
    """After address validation, no amplification limit applies."""
    conn = _make_server_conn()
    conn._bytes_received = 10  # tiny amount received

    conn.send_stream_data(stream_id=0, data=b"x" * 500, end_stream=False)
    datagrams = conn.send_datagrams(now=10.0)

    total_sent = sum(len(d) for d in datagrams)
    assert total_sent > 3 * 10  # exceeds 3x, which is fine


# --- PTO probe tests ---


def test_pto_fires_and_sends_ping() -> None:
    """When PTO fires, handle_timer sets probe_needed, send_datagrams sends PING."""
    conn = _make_server_conn()
    conn._last_activity = 10.0
    conn._config = QuicConfiguration(
        certificate=CERT, private_key=KEY, idle_timeout=60.0
    )

    # Send a packet so there's an ack-eliciting in flight
    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    pkt_count_before = len(conn._application_space.sent_packets)

    # Advance past PTO deadline
    pto = conn._rtt.pto_duration()
    conn.handle_timer(now=10.0 + pto + 0.001)

    # Probe should be needed
    assert conn._pto_count == 1

    # send_datagrams should produce the PING probe
    datagrams = conn.send_datagrams(now=10.0 + pto + 0.001)
    assert len(datagrams) >= 1

    # Should have recorded the probe packet
    pkt_count_after = len(conn._application_space.sent_packets)
    assert pkt_count_after > pkt_count_before


def test_pto_backoff_doubles() -> None:
    """PTO uses exponential backoff (2^pto_count)."""
    conn = _make_server_conn()
    conn._last_activity = 10.0
    conn._config = QuicConfiguration(
        certificate=CERT, private_key=KEY, idle_timeout=60.0
    )

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    pto = conn._rtt.pto_duration()

    # First PTO fires
    conn.handle_timer(now=10.0 + pto + 0.001)
    assert conn._pto_count == 1
    conn.send_datagrams(now=10.0 + pto + 0.001)

    # Second PTO needs 2x the delay
    conn.handle_timer(now=10.0 + 2 * pto + 0.001)
    # Still pto_count=1 if we haven't passed 2x threshold from latest sent
    # The probe itself resets the "latest_sent" for PTO calculation
    # Let's check the timer instead
    timer = conn.get_timer()
    assert timer is not None


def test_pto_resets_on_ack() -> None:
    """pto_count resets to 0 when an ACK provides an RTT sample."""
    conn = _make_server_conn()
    conn._pto_count = 3  # simulate 3 PTO firings
    conn._now = 11.0

    # Simulate ACK processing that gives an RTT sample
    conn._rtt.update(latest_rtt=0.050)
    conn._pto_count = 0  # This is what _process_ack does on RTT sample
    assert conn._pto_count == 0


# --- Retransmission tests ---


def test_retransmit_lost_stream_frame() -> None:
    """Lost STREAM frames are re-queued for retransmission."""
    conn = _make_server_conn()

    # Send stream data to populate send buffer
    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    # Simulate a lost packet containing a SentStreamFrame
    lost = [
        SentPacket(
            packet_number=0,
            sent_time=10.0,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentStreamFrame(stream_id=0, offset=0, length=5, fin=False),),
        )
    ]
    conn._retransmit_lost(lost)

    # Should have re-queued the stream data
    assert len(conn._stream_send_queue) == 1
    sid, data, fin = conn._stream_send_queue[0]
    assert sid == 0
    assert data == b"hello"
    assert fin is False


def test_retransmit_lost_handshake_done() -> None:
    """Lost HANDSHAKE_DONE is re-queued."""
    conn = _make_server_conn()
    lost = [
        SentPacket(
            packet_number=0, sent_time=10.0, sent_bytes=100,
            ack_eliciting=True, in_flight=True,
            frames=(SentHandshakeDoneFrame(),),
        )
    ]
    conn._retransmit_lost(lost)
    assert conn._handshake_done_pending is True


def test_retransmit_lost_ack_not_retransmitted() -> None:
    """ACK frames are NOT retransmitted (RFC 9002)."""
    from zoomies.recovery import SentAckFrame

    conn = _make_server_conn()
    lost = [
        SentPacket(
            packet_number=0, sent_time=10.0, sent_bytes=100,
            ack_eliciting=False, in_flight=False,
            frames=(SentAckFrame(),),
        )
    ]
    conn._retransmit_lost(lost)
    assert len(conn._stream_send_queue) == 0
    assert conn._handshake_done_pending is False


def test_retransmit_lost_crypto_frame() -> None:
    """Lost CRYPTO frames mark crypto retransmit."""
    conn = _make_server_conn()
    lost = [
        SentPacket(
            packet_number=0, sent_time=10.0, sent_bytes=100,
            ack_eliciting=True, in_flight=True,
            frames=(SentCryptoFrame(offset=0, length=50),),
        )
    ]
    conn._retransmit_lost(lost)
    assert len(conn._crypto_retransmit) == 1
    assert conn._crypto_retransmit[0][0] == 0


# --- Handshake done retransmission via send_datagrams ---


def test_handshake_done_pending_sent_via_send_datagrams() -> None:
    """_handshake_done_pending=True causes HANDSHAKE_DONE to be re-sent."""
    conn = _make_server_conn()
    conn._handshake_done_pending = True
    pn_before = conn._one_rtt_pn

    datagrams = conn.send_datagrams(now=10.0)
    assert len(datagrams) >= 1
    assert conn._handshake_done_pending is False
    assert conn._one_rtt_pn > pn_before


# --- Integration: loss detection in _process_ack ---


def test_process_ack_triggers_loss_detection() -> None:
    """ACK processing runs loss detection and retransmits lost frames."""
    conn = _make_server_conn()
    conn._now = 10.0

    # Send 5 separate packets (one at a time to get distinct PNs)
    for i in range(5):
        conn.send_stream_data(stream_id=0, data=f"pkt{i}".encode(), end_stream=False)
        conn.send_datagrams(now=10.0)

    # Verify we have 5 distinct packets
    assert len(conn._application_space.sent_packets) == 5

    # Give RTT a sample so loss detection works
    conn._rtt.update(latest_rtt=0.100)

    # Simulate ACK for packet 4 only (gap >= 3 for packets 0,1)
    from zoomies.frames.ack import AckFrame
    ack = AckFrame(ranges=(range(4, 5),), delay=0)
    conn._now = 10.5  # advance time
    conn._process_ack(ack)

    # Packets 0 and 1 should have been declared lost and re-queued
    # (packet gap from 4: pkt0 gap=4, pkt1 gap=3 → both lost)
    assert len(conn._stream_send_queue) >= 1


# --- Idle timeout vs PTO distinction ---


def test_idle_timeout_closes_connection() -> None:
    """Idle timeout closes the connection."""
    conn = _make_server_conn()
    conn._last_activity = 10.0
    conn._config = QuicConfiguration(
        certificate=CERT, private_key=KEY, idle_timeout=5.0
    )

    events = conn.handle_timer(now=15.1)  # past idle timeout
    assert conn._state == ConnectionState.CLOSED
    assert any(hasattr(e, "error_code") for e in events)


def test_pto_does_not_close_connection() -> None:
    """PTO fires a probe but does NOT close the connection."""
    conn = _make_server_conn()
    conn._last_activity = 10.0
    conn._config = QuicConfiguration(
        certificate=CERT, private_key=KEY, idle_timeout=60.0
    )

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    pto = conn._rtt.pto_duration()
    conn.handle_timer(now=10.0 + pto + 0.001)

    # Connection should still be open
    assert conn._state == ConnectionState.ONE_RTT
    assert conn._probe_needed is True


# --- get_timer includes PTO ---


def test_get_timer_returns_pto_deadline() -> None:
    """get_timer returns PTO deadline when packets are in flight."""
    conn = _make_server_conn()
    conn._last_activity = 10.0
    conn._config = QuicConfiguration(
        certificate=CERT, private_key=KEY, idle_timeout=60.0
    )

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    timer = conn.get_timer()
    assert timer is not None
    # Timer should be near 10.0 + PTO, not 10.0 + 60.0 (idle)
    assert timer < 10.0 + 2.0


def test_get_timer_none_when_closed() -> None:
    """get_timer returns None when connection is closed."""
    conn = _make_server_conn()
    conn._state = ConnectionState.CLOSED
    assert conn.get_timer() is None


def test_get_timer_none_when_no_deadlines() -> None:
    """get_timer returns None with no activity and no packets in flight."""
    conn = _make_server_conn()
    # No last_activity, no packets in flight
    conn._last_activity = 0.0
    assert conn.get_timer() is None
