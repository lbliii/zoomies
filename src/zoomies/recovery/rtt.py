"""RTT estimation for QUIC loss detection (RFC 9002 §5.3)."""

from dataclasses import dataclass, field

# RFC 9002 §6.2.2: initial RTT before any samples
INITIAL_RTT = 0.333  # 333ms
# RFC 9002 §6.2: granularity for timer calculations
TIMER_GRANULARITY = 0.001  # 1ms


@dataclass(slots=True)
class RttEstimator:
    """RTT estimator per RFC 9002 §5.3.

    Maintains smoothed_rtt, rttvar, min_rtt, and latest_rtt.
    All values in seconds (float).
    """

    min_rtt: float = float("inf")
    smoothed_rtt: float = INITIAL_RTT
    rttvar: float = INITIAL_RTT / 2.0
    latest_rtt: float = 0.0
    _first_sample: bool = field(default=True, repr=False)

    def update(
        self,
        latest_rtt: float,
        ack_delay: float = 0.0,
        handshake_confirmed: bool = False,
    ) -> None:
        """Update RTT estimates with a new sample (RFC 9002 §5.3).

        Args:
            latest_rtt: Measured RTT for the newly acknowledged packet.
            ack_delay: Peer's ACK delay from the ACK frame (in seconds).
            handshake_confirmed: Whether the handshake is confirmed.
        """
        self.latest_rtt = latest_rtt
        self.min_rtt = min(self.min_rtt, latest_rtt)

        if self._first_sample:
            self.smoothed_rtt = latest_rtt
            self.rttvar = latest_rtt / 2.0
            self._first_sample = False
            return

        # RFC 9002 §5.3: adjust for ACK delay only after handshake confirmed
        # and only if it doesn't push below min_rtt
        adjusted_rtt = latest_rtt
        if handshake_confirmed and ack_delay > 0:
            adjusted_rtt = max(latest_rtt - ack_delay, self.min_rtt)

        # EWMA update
        self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.smoothed_rtt - adjusted_rtt)
        self.smoothed_rtt = 0.875 * self.smoothed_rtt + 0.125 * adjusted_rtt

    def pto_duration(self) -> float:
        """Probe Timeout duration (RFC 9002 §6.2.1).

        PTO = smoothed_rtt + max(4 * rttvar, granularity)
        """
        return self.smoothed_rtt + max(4.0 * self.rttvar, TIMER_GRANULARITY)

    @property
    def has_samples(self) -> bool:
        """True if at least one RTT sample has been received."""
        return not self._first_sample
