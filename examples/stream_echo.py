"""
Recovery and stream reassembly — demonstrates 0.2.0 protocol features.

Shows the key building blocks added in 0.2.0: ordered stream reassembly,
RTT estimation, loss detection, and NewReno congestion control. Each component
is exercised in isolation (sans-I/O style), then composed into a simulated
connection loop that handles packet loss via PTO retransmission.

Run from repo root:
    uv run python -m examples.stream_echo
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoomies.core.stream import Stream
from zoomies.frames.stream import StreamFrame
from zoomies.primitives import StreamId
from zoomies.recovery import (
    CongestionController,
    PacketSpace,
    RttEstimator,
    SentPacket,
    SentStreamFrame,
)


def demo_stream_reassembly() -> None:
    """Stream reassembly: out-of-order frames delivered in order."""
    print("=== Stream Reassembly ===\n")

    stream = Stream(StreamId(0))

    # Simulate out-of-order arrival (later chunk arrives first)
    chunks = [
        (8, b" works!", True),  # arrives first (offset 8, with FIN)
        (0, b"Recovery", False),  # arrives second (offset 0, fills the gap)
    ]

    for offset, data, fin in chunks:
        frame = StreamFrame(stream_id=StreamId(0), offset=offset, data=data, fin=fin)
        delivered = stream.add_receive_frame(frame)
        if delivered:
            print(f"  Frame(offset={offset}, {len(data)}B, fin={fin}) -> delivered: {delivered!r}")
        else:
            print(
                f"  Frame(offset={offset}, {len(data)}B, fin={fin}) -> buffered (waiting for gap)"
            )

    print(f"\n  Complete: {stream.receive_complete}")
    print(f"  Bytes delivered: {stream.bytes_delivered}")


def demo_rtt_estimation() -> None:
    """RTT estimation: EWMA smoothing per RFC 9002 §5.3."""
    print("\n=== RTT Estimation (EWMA) ===\n")

    rtt = RttEstimator()
    print(f"  Initial: smoothed={rtt.smoothed_rtt:.3f}s, rttvar={rtt.rttvar:.3f}s")
    print(f"  PTO duration: {rtt.pto_duration():.3f}s")

    # Feed RTT samples (simulating improving network conditions)
    samples = [0.100, 0.095, 0.088, 0.090, 0.085, 0.082, 0.080]
    for sample in samples:
        rtt.update(sample, handshake_confirmed=True)
        print(
            f"  Sample {sample:.3f}s -> smoothed={rtt.smoothed_rtt:.3f}s, "
            f"min={rtt.min_rtt:.3f}s, PTO={rtt.pto_duration():.3f}s"
        )


def demo_congestion_control() -> None:
    """NewReno congestion control: slow start, loss, recovery."""
    print("\n=== Congestion Control (NewReno) ===\n")

    cc = CongestionController()
    print(f"  Initial cwnd: {cc.congestion_window} bytes (slow start)")
    print(f"  Can send 1200B: {cc.can_send(1200)}")

    # Slow start: send and ACK packets, window grows
    print("\n  -- Slow start phase --")
    for i in range(5):
        cc.on_packet_sent(1200)
        pkt = SentPacket(
            packet_number=i,
            sent_time=float(i),
            sent_bytes=1200,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentStreamFrame(stream_id=0, offset=i * 1200, length=1200, fin=False),),
        )
        cc.on_packets_acked([pkt])
        print(f"  Packet {i}: cwnd={cc.congestion_window}, in_flight={cc.bytes_in_flight}")

    # Loss event: window halves
    print("\n  -- Loss event --")
    lost_pkt = SentPacket(
        packet_number=5,
        sent_time=5.0,
        sent_bytes=1200,
        ack_eliciting=True,
        in_flight=True,
        frames=(SentStreamFrame(stream_id=0, offset=6000, length=1200, fin=False),),
    )
    cc.on_packet_sent(1200)
    cc.on_packets_lost([lost_pkt], now=6.0)
    print(f"  After loss: cwnd={cc.congestion_window}, ssthresh={cc.ssthresh}")


def demo_loss_detection() -> None:
    """Packet space tracking and PTO-driven retransmission."""
    print("\n=== Loss Detection & PTO ===\n")

    space = PacketSpace()
    rtt = RttEstimator()
    rtt.update(0.050)  # 50ms RTT

    # Register sent packets
    for pn in range(5):
        space.on_packet_sent(
            packet_number=pn,
            sent_time=pn * 0.01,
            sent_bytes=100,
            ack_eliciting=True,
            in_flight=True,
            frames=(SentStreamFrame(stream_id=0, offset=pn * 100, length=100, fin=pn == 4),),
        )
    print(f"  Sent 5 packets, in_flight={space.has_ack_eliciting_in_flight}")

    # ACK packets 0, 1, 3, 4 (packet 2 missing -> lost)
    # on_ack_received takes range objects: [start, stop)
    acked = space.on_ack_received([range(2), range(3, 5)])
    pns = [p.packet_number for p in acked]
    remaining = sorted(space.sent_packets.keys())
    print(f"  ACKed: {pns}, remaining: {remaining}")

    # Detect losses (packet 2 has gap of 2 from largest_acked=4)
    # RFC 9002 §6.1: packet-number threshold = 3, so gap of 2 isn't enough.
    # Use time threshold instead: packet 2 was sent long ago relative to RTT.
    from zoomies.recovery.loss_detection import detect_lost_packets

    lost = detect_lost_packets(
        sent_packets=space.sent_packets,
        largest_acked=space.largest_acked_packet,
        now=0.1,
        rtt=rtt,
    )
    for pkt in lost:
        print(f"  Lost: packet {pkt.packet_number} (sent at {pkt.sent_time:.3f}s)")

    # PTO calculation
    pto = rtt.pto_duration()
    print(f"\n  PTO duration: {pto:.3f}s (smoothed={rtt.smoothed_rtt:.3f}s)")
    print(f"  After 2 PTO backoffs: {pto * 4:.3f}s (exponential)")


def demo_timer_loop() -> None:
    """Sans-I/O timer-driven recovery loop using QuicConnection.

    Demonstrates the get_timer() / handle_timer() pattern that callers
    must implement. Uses a real client-server handshake (no private API).
    """
    print("\n=== Sans-I/O Timer Loop ===\n")

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert_path = os.path.join(repo, "tests", "fixtures", "ssl_cert.pem")
    key_path = os.path.join(repo, "tests", "fixtures", "ssl_key.pem")

    if not os.path.exists(cert_path):
        print("  (skipped — run 'python scripts/generate_fixtures.py' first)")
        return

    with open(cert_path, "rb") as f:
        cert = f.read()
    with open(key_path, "rb") as f:
        key = f.read()

    import time

    from zoomies.core import QuicConfiguration, QuicConnection
    from zoomies.events import ConnectionClosed, HandshakeComplete

    ADDR = ("127.0.0.1", 4433)

    # --- Set up client and server ---
    server_config = QuicConfiguration(certificate=cert, private_key=key)
    client_config = QuicConfiguration(
        is_client=True, verify_mode=False, ca_certs=None  # loopback demo
    )

    server = QuicConnection(server_config)
    client = QuicConnection(client_config)

    # --- Perform handshake via loopback ---
    now = time.monotonic()
    client.connect()
    for dg in client.send_datagrams(now=now):
        events = server.datagram_received(dg, ADDR, now=now)
    for dg in server.send_datagrams(now=now):
        events = client.datagram_received(dg, ADDR, now=now)
    for dg in client.send_datagrams(now=now):
        events = server.datagram_received(dg, ADDR, now=now)
    for dg in server.send_datagrams(now=now):
        events = client.datagram_received(dg, ADDR, now=now)

    print("  Handshake complete (client-server loopback)")

    # --- Client sends stream data, then we stop forwarding ACKs ---
    client.send_stream_data(stream_id=0, data=b"timer demo", end_stream=True)
    datagrams = client.send_datagrams(now=now)
    print(f"  Client sent {len(datagrams)} datagram(s)")

    # Sans-I/O timer pattern: the caller drives the clock.
    # We intentionally don't deliver these datagrams to the server,
    # so no ACK comes back — PTO will fire and retransmit.
    print("  Simulating no ACKs (PTO retransmission):\n")
    start = now
    for _tick in range(8):
        now += 0.25  # advance 250ms per tick
        timer = client.get_timer()
        if timer is not None and now >= timer:
            events = client.handle_timer(now)
            retransmit = client.send_datagrams(now=now)
            closed = any(isinstance(e, ConnectionClosed) for e in events)
            print(
                f"  t={now - start:.2f}s: timer fired, "
                f"retransmit={len(retransmit)} pkt(s), "
                f"closed={closed}"
            )
            if closed:
                break


if __name__ == "__main__":
    demo_stream_reassembly()
    demo_rtt_estimation()
    demo_congestion_control()
    demo_loss_detection()
    demo_timer_loop()
    print("\nDone.")
