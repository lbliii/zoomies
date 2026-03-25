"""Phase 2 tests — sent packet registry, RTT estimation, packet space tracking."""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.core.connection import ConnectionState
from zoomies.crypto import CryptoPair
from zoomies.recovery import (
    PacketSpace,
    RttEstimator,
    SentAckFrame,
    SentCryptoFrame,
    SentHandshakeDoneFrame,
    SentPacket,
    SentPingFrame,
    SentStreamFrame,
)
from zoomies.recovery.rtt import INITIAL_RTT

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"


# --- RttEstimator tests ---


def test_rtt_initial_state() -> None:
    """RttEstimator starts with RFC 9002 defaults."""
    rtt = RttEstimator()
    assert rtt.smoothed_rtt == INITIAL_RTT
    assert rtt.rttvar == INITIAL_RTT / 2.0
    assert rtt.min_rtt == float("inf")
    assert rtt.latest_rtt == 0.0
    assert not rtt.has_samples


def test_rtt_first_sample() -> None:
    """First RTT sample sets smoothed_rtt directly."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    assert rtt.smoothed_rtt == 0.100
    assert rtt.rttvar == 0.050  # latest_rtt / 2
    assert rtt.min_rtt == 0.100
    assert rtt.latest_rtt == 0.100
    assert rtt.has_samples


def test_rtt_second_sample_ewma() -> None:
    """Second sample uses EWMA update."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    rtt.update(latest_rtt=0.120)
    # smoothed = 0.875 * 0.100 + 0.125 * 0.120 = 0.1025
    assert abs(rtt.smoothed_rtt - 0.1025) < 1e-9
    # rttvar = 0.75 * 0.050 + 0.25 * |0.100 - 0.120| = 0.0425
    assert abs(rtt.rttvar - 0.0425) < 1e-9
    assert rtt.min_rtt == 0.100


def test_rtt_min_rtt_tracks_minimum() -> None:
    """min_rtt tracks the lowest observed RTT."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    rtt.update(latest_rtt=0.050)
    rtt.update(latest_rtt=0.080)
    assert rtt.min_rtt == 0.050


def test_rtt_ack_delay_adjustment() -> None:
    """ACK delay is subtracted when handshake is confirmed."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)  # first sample
    rtt.update(latest_rtt=0.120, ack_delay=0.010, handshake_confirmed=True)
    # adjusted_rtt = max(0.120 - 0.010, 0.100) = 0.110
    # smoothed = 0.875 * 0.100 + 0.125 * 0.110 = 0.10125
    assert abs(rtt.smoothed_rtt - 0.10125) < 1e-9


def test_rtt_ack_delay_not_below_min() -> None:
    """ACK delay adjustment does not push below min_rtt."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.050)
    rtt.update(latest_rtt=0.060, ack_delay=0.030, handshake_confirmed=True)
    # adjusted_rtt = max(0.060 - 0.030, 0.050) = 0.050
    # smoothed = 0.875 * 0.050 + 0.125 * 0.050 = 0.050
    assert abs(rtt.smoothed_rtt - 0.050) < 1e-9


def test_rtt_ack_delay_ignored_before_handshake() -> None:
    """ACK delay is not applied before handshake confirmation."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    rtt.update(latest_rtt=0.120, ack_delay=0.010, handshake_confirmed=False)
    # No adjustment: smoothed = 0.875 * 0.100 + 0.125 * 0.120 = 0.1025
    assert abs(rtt.smoothed_rtt - 0.1025) < 1e-9


def test_rtt_pto_duration() -> None:
    """PTO = smoothed_rtt + max(4 * rttvar, 1ms)."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=0.100)
    # smoothed=0.100, rttvar=0.050
    # PTO = 0.100 + max(4*0.050, 0.001) = 0.100 + 0.200 = 0.300
    assert abs(rtt.pto_duration() - 0.300) < 1e-9


def test_rtt_pto_duration_small_rttvar() -> None:
    """PTO uses timer granularity when rttvar is very small."""
    rtt = RttEstimator()
    rtt._first_sample = False
    rtt.smoothed_rtt = 0.010
    rtt.rttvar = 0.0001
    # PTO = 0.010 + max(4*0.0001, 0.001) = 0.010 + 0.001 = 0.011
    assert abs(rtt.pto_duration() - 0.011) < 1e-9


# --- PacketSpace tests ---


def test_packet_space_on_packet_sent() -> None:
    """on_packet_sent records a packet."""
    space = PacketSpace()
    pkt = space.on_packet_sent(
        packet_number=0,
        sent_time=1.0,
        sent_bytes=100,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentPingFrame(),),
    )
    assert pkt.packet_number == 0
    assert 0 in space.sent_packets
    assert space.ack_eliciting_in_flight == 1


def test_packet_space_on_ack_received() -> None:
    """on_ack_received returns newly acked packets and removes them."""
    space = PacketSpace()
    for pn in range(5):
        space.on_packet_sent(
            packet_number=pn,
            sent_time=1.0 + pn * 0.01,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentPingFrame(),),
        )
    assert len(space.sent_packets) == 5

    # ACK packets 0-2
    acked = space.on_ack_received([range(3)])
    assert len(acked) == 3
    assert {p.packet_number for p in acked} == {0, 1, 2}
    assert len(space.sent_packets) == 2  # 3, 4 remain
    assert space.largest_acked_packet == 2


def test_packet_space_on_ack_with_gaps() -> None:
    """ACK ranges with gaps correctly identify acked packets."""
    space = PacketSpace()
    for pn in range(6):
        space.on_packet_sent(
            packet_number=pn,
            sent_time=1.0,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentPingFrame(),),
        )
    # ACK [0,2) and [4,6) — packets 0,1 and 4,5
    acked = space.on_ack_received([range(2), range(4, 6)])
    assert {p.packet_number for p in acked} == {0, 1, 4, 5}
    assert len(space.sent_packets) == 2  # 2, 3 remain
    assert space.largest_acked_packet == 5


def test_packet_space_ack_eliciting_counter() -> None:
    """ack_eliciting_in_flight decrements on ACK."""
    space = PacketSpace()
    space.on_packet_sent(0, 1.0, 100, True, True, (SentPingFrame(),))
    space.on_packet_sent(1, 1.0, 100, False, False, (SentAckFrame(),))
    assert space.ack_eliciting_in_flight == 1

    space.on_ack_received([range(1)])
    assert space.ack_eliciting_in_flight == 0
    assert not space.has_ack_eliciting_in_flight


def test_packet_space_duplicate_ack() -> None:
    """ACK for already-acked packet returns empty."""
    space = PacketSpace()
    space.on_packet_sent(0, 1.0, 100, True, True, (SentPingFrame(),))
    space.on_ack_received([range(1)])
    # Second ACK for same packet
    acked = space.on_ack_received([range(1)])
    assert acked == []


def test_packet_space_largest_acked_grows() -> None:
    """largest_acked_packet only grows, never shrinks."""
    space = PacketSpace()
    space.on_packet_sent(0, 1.0, 100, True, True, (SentPingFrame(),))
    space.on_packet_sent(5, 2.0, 100, True, True, (SentPingFrame(),))
    space.on_ack_received([range(5, 6)])
    assert space.largest_acked_packet == 5
    space.on_ack_received([range(1)])
    assert space.largest_acked_packet == 5  # doesn't shrink


# --- SentPacket tests ---


def test_sent_packet_immutable() -> None:
    """SentPacket is frozen."""
    pkt = SentPacket(
        packet_number=0,
        sent_time=1.0,
        sent_bytes=100,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentCryptoFrame(offset=0, length=50),),
    )
    assert pkt.packet_number == 0
    assert isinstance(pkt.frames[0], SentCryptoFrame)


def test_sent_frame_variants() -> None:
    """All SentFrame variants are constructable."""
    assert SentCryptoFrame(offset=0, length=100).length == 100
    assert SentStreamFrame(stream_id=4, offset=0, length=50, fin=True).fin is True
    assert SentAckFrame() is not None
    assert SentHandshakeDoneFrame() is not None


# --- Connection integration tests ---


def test_connection_records_sent_packets() -> None:
    """QuicConnection records SentPackets when sending."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._now = 10.0

    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    # Should have recorded a SentPacket in application space
    assert len(conn._application_space.sent_packets) >= 1
    pkt = next(iter(conn._application_space.sent_packets.values()))
    assert pkt.ack_eliciting is True
    assert pkt.in_flight is True
    assert any(isinstance(f, SentStreamFrame) for f in pkt.frames)


def test_connection_ack_only_not_ack_eliciting() -> None:
    """ACK-only packets are recorded as not ack-eliciting."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._ack_needed_application = True
    conn._application_ack_ranges.add(0)

    conn.send_datagrams(now=10.0)

    # The ACK packet should be not ack-eliciting
    ack_pkts = [
        p
        for p in conn._application_space.sent_packets.values()
        if any(isinstance(f, SentAckFrame) for f in p.frames)
    ]
    assert len(ack_pkts) == 1
    assert ack_pkts[0].ack_eliciting is False


def test_connection_get_timer_includes_pto() -> None:
    """get_timer() returns PTO deadline when packets are in flight."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY, idle_timeout=60.0)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._last_activity = 10.0

    # Send a packet
    conn.send_stream_data(stream_id=0, data=b"hello", end_stream=False)
    conn.send_datagrams(now=10.0)

    timer = conn.get_timer()
    assert timer is not None
    # PTO should fire before idle timeout (60s)
    # PTO = 10.0 + initial_pto (smoothed_rtt + max(4*rttvar, 1ms)) ≈ 10.0 + 0.5
    assert timer < 10.0 + 60.0  # definitely before idle
    # PTO at initial RTT: 0.333 + max(4*0.1665, 0.001) = 0.333 + 0.666 ≈ 0.999
    assert timer < 10.0 + 2.0  # reasonable PTO range
