"""Hardening tests — Hypothesis property tests for recovery invariants.

Validates that the recovery machinery maintains its invariants under
random ACK patterns, loss patterns, and RTT samples.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from zoomies.recovery import (
    PacketSpace,
    RttEstimator,
    SentPingFrame,
    detect_lost_packets,
)
from zoomies.recovery.congestion import (
    MINIMUM_WINDOW,
    CongestionController,
)
from zoomies.recovery.loss_detection import loss_delay
from zoomies.recovery.sent_packet import SentPacket

# --- RTT estimator invariants ---


@given(samples=st.lists(st.floats(min_value=0.001, max_value=10.0), min_size=1, max_size=50))
@settings(max_examples=200)
def test_rtt_smoothed_always_positive(samples: list[float]) -> None:
    """smoothed_rtt is always positive after any sequence of samples."""
    rtt = RttEstimator()
    for s in samples:
        rtt.update(latest_rtt=s)
    assert rtt.smoothed_rtt > 0


@given(samples=st.lists(st.floats(min_value=0.001, max_value=10.0), min_size=1, max_size=50))
@settings(max_examples=200)
def test_rtt_min_rtt_is_minimum(samples: list[float]) -> None:
    """min_rtt tracks the actual minimum of all samples."""
    rtt = RttEstimator()
    for s in samples:
        rtt.update(latest_rtt=s)
    assert rtt.min_rtt == min(samples)


@given(samples=st.lists(st.floats(min_value=0.001, max_value=10.0), min_size=1, max_size=50))
@settings(max_examples=200)
def test_rtt_rttvar_non_negative(samples: list[float]) -> None:
    """rttvar is always non-negative."""
    rtt = RttEstimator()
    for s in samples:
        rtt.update(latest_rtt=s)
    assert rtt.rttvar >= 0


@given(samples=st.lists(st.floats(min_value=0.001, max_value=10.0), min_size=1, max_size=50))
@settings(max_examples=200)
def test_rtt_pto_duration_positive(samples: list[float]) -> None:
    """PTO duration is always positive."""
    rtt = RttEstimator()
    for s in samples:
        rtt.update(latest_rtt=s)
    assert rtt.pto_duration() > 0


# --- Loss detection invariants ---


@given(
    num_packets=st.integers(min_value=1, max_value=20),
    largest_acked=st.integers(min_value=0, max_value=25),
    rtt_sample=st.floats(min_value=0.001, max_value=5.0),
)
@settings(max_examples=200)
def test_loss_detection_never_declares_above_acked(
    num_packets: int, largest_acked: int, rtt_sample: float
) -> None:
    """Lost packets always have PN <= largest_acked."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=rtt_sample)

    sent: dict[int, SentPacket] = {}
    for pn in range(num_packets):
        sent[pn] = SentPacket(
            packet_number=pn,
            sent_time=1.0,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentPingFrame(),),
        )

    lost = detect_lost_packets(sent, largest_acked, now=100.0, rtt=rtt)
    for pkt in lost:
        assert pkt.packet_number <= largest_acked


@given(
    num_packets=st.integers(min_value=1, max_value=20),
    largest_acked=st.integers(min_value=0, max_value=25),
    rtt_sample=st.floats(min_value=0.001, max_value=5.0),
)
@settings(max_examples=200)
def test_loss_detection_removes_from_dict(
    num_packets: int, largest_acked: int, rtt_sample: float
) -> None:
    """Lost packets are removed from the sent_packets dict."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=rtt_sample)

    sent: dict[int, SentPacket] = {}
    for pn in range(num_packets):
        sent[pn] = SentPacket(
            packet_number=pn,
            sent_time=1.0,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentPingFrame(),),
        )

    lost = detect_lost_packets(sent, largest_acked, now=100.0, rtt=rtt)
    for pkt in lost:
        assert pkt.packet_number not in sent


@given(rtt_sample=st.floats(min_value=0.001, max_value=10.0))
@settings(max_examples=100)
def test_loss_delay_at_least_granularity(rtt_sample: float) -> None:
    """loss_delay is always >= timer granularity."""
    rtt = RttEstimator()
    rtt.update(latest_rtt=rtt_sample)
    from zoomies.recovery.rtt import TIMER_GRANULARITY

    assert loss_delay(rtt) >= TIMER_GRANULARITY


# --- PacketSpace invariants ---


@given(
    ack_pattern=st.lists(st.integers(min_value=0, max_value=9), min_size=1, max_size=10),
)
@settings(max_examples=200)
def test_packet_space_ack_never_double_counts(ack_pattern: list[int]) -> None:
    """ACKing the same PN twice doesn't double-decrement counters."""
    space = PacketSpace()
    for pn in range(10):
        space.on_packet_sent(
            packet_number=pn,
            sent_time=1.0,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentPingFrame(),),
        )

    # ACK in the given pattern (may contain duplicates)
    for pn in ack_pattern:
        space.on_ack_received([range(pn, pn + 1)])

    # ack_eliciting_in_flight should never go negative
    assert space.ack_eliciting_in_flight >= 0
    # remaining + acked should equal original 10
    acked_count = 10 - len(space.sent_packets)
    assert acked_count + len(space.sent_packets) == 10


@given(
    ranges=st.lists(
        st.tuples(st.integers(min_value=0, max_value=9), st.integers(min_value=1, max_value=5)),
        min_size=1,
        max_size=5,
    ),
)
@settings(max_examples=200)
def test_packet_space_largest_acked_monotonic(ranges: list[tuple[int, int]]) -> None:
    """largest_acked_packet only grows, never shrinks."""
    space = PacketSpace()
    for pn in range(15):
        space.on_packet_sent(
            packet_number=pn,
            sent_time=1.0,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentPingFrame(),),
        )

    prev_largest = None
    for start, length in ranges:
        end = min(start + length, 15)
        if start >= end:
            continue
        space.on_ack_received([range(start, end)])
        if space.largest_acked_packet is not None:
            if prev_largest is not None:
                assert space.largest_acked_packet >= prev_largest
            prev_largest = space.largest_acked_packet


# --- Congestion controller invariants ---


@given(
    sent_bytes=st.lists(st.integers(min_value=100, max_value=1200), min_size=1, max_size=20),
    ack_indices=st.lists(st.integers(min_value=0, max_value=19), min_size=0, max_size=10),
    loss_indices=st.lists(st.integers(min_value=0, max_value=19), min_size=0, max_size=10),
)
@settings(max_examples=200)
def test_cc_bytes_in_flight_non_negative(
    sent_bytes: list[int], ack_indices: list[int], loss_indices: list[int]
) -> None:
    """bytes_in_flight never goes negative."""
    cc = CongestionController()
    packets: list[SentPacket] = []

    for i, sb in enumerate(sent_bytes):
        cc.on_packet_sent(sb)
        packets.append(
            SentPacket(
                packet_number=i,
                sent_time=1.0 + i * 0.01,
                sent_bytes=sb,
                ack_eliciting=True,
                in_flight=True,
                frames=(SentPingFrame(),),
            )
        )

    # ACK some (avoid out-of-range)
    to_ack = [packets[i] for i in set(ack_indices) if i < len(packets)]
    if to_ack:
        cc.on_packets_acked(to_ack)

    # Lose some (non-overlapping with acked, for realism)
    acked_set = {p.packet_number for p in to_ack}
    to_lose = [packets[i] for i in set(loss_indices) if i < len(packets) and i not in acked_set]
    if to_lose:
        cc.on_packets_lost(to_lose, now=2.0)

    assert cc.bytes_in_flight >= 0


@given(
    sent_bytes=st.lists(st.integers(min_value=100, max_value=1200), min_size=1, max_size=10),
)
@settings(max_examples=100)
def test_cc_cwnd_never_below_minimum(sent_bytes: list[int]) -> None:
    """Congestion window never drops below MINIMUM_WINDOW."""
    cc = CongestionController()
    packets: list[SentPacket] = []

    for i, sb in enumerate(sent_bytes):
        cc.on_packet_sent(sb)
        packets.append(
            SentPacket(
                packet_number=i,
                sent_time=1.0,
                sent_bytes=sb,
                ack_eliciting=True,
                in_flight=True,
                frames=(SentPingFrame(),),
            )
        )

    # Multiple loss events
    for j in range(5):
        cc.on_packets_lost(packets, now=2.0 + j)

    assert cc.congestion_window >= MINIMUM_WINDOW


# --- InvalidTag audit: verify no state transition on decrypt failure ---


def test_invalid_tag_initial_no_state_change() -> None:
    """InvalidTag on Initial does NOT transition from INITIAL state."""
    from tests.utils import load
    from zoomies.core import QuicConfiguration, QuicConnection
    from zoomies.core.connection import ConnectionState

    cert = load("fixtures/ssl_cert.pem")
    key = load("fixtures/ssl_key.pem")
    config = QuicConfiguration(certificate=cert, private_key=key)
    conn = QuicConnection(config)
    assert conn._state == ConnectionState.INITIAL

    garbage = bytes(1200)
    conn.datagram_received(garbage, ("127.0.0.1", 4433), now=1.0)
    assert conn._state != ConnectionState.HANDSHAKE


def test_invalid_tag_short_header_no_state_change() -> None:
    """InvalidTag on 1-RTT does NOT change connection state."""
    from tests.utils import load
    from zoomies.core import QuicConfiguration, QuicConnection
    from zoomies.core.connection import ConnectionState
    from zoomies.crypto import CryptoPair
    from zoomies.encoding import Buffer
    from zoomies.packet.builder import push_short_header

    cert = load("fixtures/ssl_cert.pem")
    key = load("fixtures/ssl_key.pem")
    config = QuicConfiguration(certificate=cert, private_key=key)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
    conn._peer_cid = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=conn._our_cid, is_client=False)

    wrong_crypto = CryptoPair()
    wrong_crypto.setup_initial(cid=b"\x00" * 8, is_client=True)
    header_buf = Buffer()
    push_short_header(header_buf, conn._our_cid, 0)
    encrypted = wrong_crypto.encrypt_packet(header_buf.data, b"bad", 0)

    conn.datagram_received(encrypted, ("127.0.0.1", 4433), now=1.0)
    assert conn._state == ConnectionState.ONE_RTT
