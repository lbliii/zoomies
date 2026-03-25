"""NewReno congestion control (RFC 9002 §7).

Implements the core NewReno algorithm: slow start, congestion avoidance,
and loss-based window reduction.
"""

from zoomies.recovery.sent_packet import SentPacket

# RFC 9002 §7.2: Initial window
MAX_DATAGRAM_SIZE = 1200
INITIAL_WINDOW = 10 * MAX_DATAGRAM_SIZE
# RFC 9002 §7.2: Minimum window
MINIMUM_WINDOW = 2 * MAX_DATAGRAM_SIZE


class CongestionController:
    """NewReno congestion controller (RFC 9002 §7)."""

    def __init__(self) -> None:
        self.congestion_window: int = INITIAL_WINDOW
        self.bytes_in_flight: int = 0
        self.ssthresh: int = 2**62  # infinity until first loss
        self._congestion_recovery_start: float = 0.0

    def can_send(self, bytes_to_send: int = 0) -> bool:
        """True if the congestion window allows sending."""
        return self.bytes_in_flight + bytes_to_send <= self.congestion_window

    def on_packet_sent(self, sent_bytes: int) -> None:
        """Record bytes sent (in-flight only)."""
        self.bytes_in_flight += sent_bytes

    def on_packets_acked(self, packets: list[SentPacket]) -> None:
        """Process newly acknowledged packets — grow window.

        RFC 9002 §7.3: Slow start doubles cwnd; congestion avoidance
        grows linearly.
        """
        for pkt in packets:
            if not pkt.in_flight:
                continue
            self.bytes_in_flight = max(0, self.bytes_in_flight - pkt.sent_bytes)
            if self.congestion_window < self.ssthresh:
                # Slow start: increase by acked bytes
                self.congestion_window += pkt.sent_bytes
            else:
                # Congestion avoidance: increase by MSS per RTT
                self.congestion_window += (
                    MAX_DATAGRAM_SIZE * pkt.sent_bytes // self.congestion_window
                )

    def on_packets_lost(self, packets: list[SentPacket], now: float) -> None:
        """Process lost packets — reduce window.

        RFC 9002 §7.3.2: On loss, halve cwnd (min = MINIMUM_WINDOW),
        set ssthresh = cwnd. Only reduce once per recovery period.
        """
        for pkt in packets:
            if not pkt.in_flight:
                continue
            self.bytes_in_flight = max(0, self.bytes_in_flight - pkt.sent_bytes)

        # Only enter recovery once per round-trip
        latest_lost = max((p.sent_time for p in packets if p.in_flight), default=0.0)
        if latest_lost <= self._congestion_recovery_start:
            return

        self._congestion_recovery_start = now
        self.congestion_window = max(self.congestion_window // 2, MINIMUM_WINDOW)
        self.ssthresh = self.congestion_window
