"""Per-space sent packet tracking for loss detection (RFC 9002)."""

from zoomies.recovery.sent_packet import SentFrame, SentPacket


class PacketSpace:
    """Tracks sent packets in a single packet number space.

    Provides on_packet_sent() to record and on_ack_received() to process ACKs.
    """

    def __init__(self) -> None:
        self._sent_packets: dict[int, SentPacket] = {}
        self.largest_acked_packet: int | None = None
        self.ack_eliciting_in_flight: int = 0

    def on_packet_sent(
        self,
        packet_number: int,
        sent_time: float,
        sent_bytes: int,
        ack_eliciting: bool,
        in_flight: bool,
        frames: tuple[SentFrame, ...],
    ) -> SentPacket:
        """Record a sent packet."""
        pkt = SentPacket(
            packet_number=packet_number,
            sent_time=sent_time,
            sent_bytes=sent_bytes,
            ack_eliciting=ack_eliciting,
            in_flight=in_flight,
            frames=frames,
        )
        self._sent_packets[packet_number] = pkt
        if ack_eliciting and in_flight:
            self.ack_eliciting_in_flight += 1
        return pkt

    def on_ack_received(self, ack_ranges: list[range]) -> list[SentPacket]:
        """Process ACK ranges; returns newly acknowledged packets.

        Args:
            ack_ranges: Sorted list of range objects [start, stop) for acked PNs.

        Returns:
            List of SentPacket that were newly acknowledged (removed from tracking).
        """
        newly_acked: list[SentPacket] = []
        for r in ack_ranges:
            for pn in range(r.start, r.stop):
                pkt = self._sent_packets.pop(pn, None)
                if pkt is not None:
                    newly_acked.append(pkt)
                    if pkt.ack_eliciting and pkt.in_flight:
                        self.ack_eliciting_in_flight = max(0, self.ack_eliciting_in_flight - 1)

        if newly_acked:
            largest = max(p.packet_number for p in newly_acked)
            if self.largest_acked_packet is None or largest > self.largest_acked_packet:
                self.largest_acked_packet = largest

        return newly_acked

    @property
    def sent_packets(self) -> dict[int, SentPacket]:
        """Read-only access to sent packets still in flight."""
        return self._sent_packets

    @property
    def has_ack_eliciting_in_flight(self) -> bool:
        """True if there are ack-eliciting packets in flight."""
        return self.ack_eliciting_in_flight > 0
