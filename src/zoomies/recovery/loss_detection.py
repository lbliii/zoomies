"""QUIC loss detection (RFC 9002 §6).

Implements both time-based and packet-number-based loss detection.
"""

from zoomies.recovery.rtt import TIMER_GRANULARITY, RttEstimator
from zoomies.recovery.sent_packet import SentPacket

# RFC 9002 §6.1.1: packet reordering threshold
PACKET_THRESHOLD = 3
# RFC 9002 §6.1.2: time reordering fraction (9/8)
TIME_THRESHOLD_NUMERATOR = 9
TIME_THRESHOLD_DENOMINATOR = 8


def loss_delay(rtt: RttEstimator) -> float:
    """Compute the time threshold for declaring a packet lost (RFC 9002 §6.1.2).

    loss_delay = max(9/8 * max(smoothed_rtt, latest_rtt), timer_granularity)
    """
    base = max(rtt.smoothed_rtt, rtt.latest_rtt)
    return max(
        base * TIME_THRESHOLD_NUMERATOR / TIME_THRESHOLD_DENOMINATOR,
        TIMER_GRANULARITY,
    )


def detect_lost_packets(
    sent_packets: dict[int, SentPacket],
    largest_acked: int | None,
    now: float,
    rtt: RttEstimator,
) -> list[SentPacket]:
    """Detect lost packets using both time and packet-number thresholds.

    RFC 9002 §6.1: A packet is declared lost if:
    - Its packet number is more than PACKET_THRESHOLD less than largest_acked, OR
    - It was sent more than loss_delay ago and a larger packet has been acked.

    Args:
        sent_packets: Currently unacknowledged sent packets (will be mutated —
            lost packets are removed).
        largest_acked: Largest packet number acknowledged so far, or None.
        now: Current time.
        rtt: RTT estimator for time threshold calculation.

    Returns:
        List of packets declared lost (removed from sent_packets).
    """
    if largest_acked is None:
        return []

    delay = loss_delay(rtt)
    lost_time = now - delay
    lost: list[SentPacket] = []

    # Iterate over a snapshot since we mutate
    for pn, pkt in list(sent_packets.items()):
        if pn > largest_acked:
            continue

        # Packet-number threshold
        pn_lost = (largest_acked - pn) >= PACKET_THRESHOLD
        # Time threshold
        time_lost = pkt.sent_time <= lost_time

        if pn_lost or time_lost:
            lost.append(pkt)

    # Remove lost packets from tracking
    for pkt in lost:
        sent_packets.pop(pkt.packet_number, None)

    return lost
