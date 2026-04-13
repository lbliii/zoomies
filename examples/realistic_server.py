"""
Realistic sans-I/O QUIC server with timer loop.

Demonstrates the full production pattern:
  1. UDP socket setup
  2. datagram_received() -> event processing -> send_datagrams() loop
  3. Timer integration (get_timer() -> select timeout -> handle_timer())
  4. Graceful shutdown

This example can accept connections from real QUIC clients (e.g. curl --http3).
It serves a simple "Hello from Zoomies!" response to any HTTP/3 request.

Run (requires cert/key in tests/fixtures/):
    uv run python -m examples.realistic_server

Then test with:
    curl --http3 -k https://localhost:4433/
"""

import os
import select
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.events import (
    ConnectionClosed,
    H3HeadersReceived,
    HandshakeComplete,
    NewSessionTicket,
    PacketDropped,
    StreamDataReceived,
)
from zoomies.h3 import H3Connection

# --- Certificate loading ---

_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cert = os.path.join(_repo, "tests", "fixtures", "ssl_cert.pem")
_key = os.path.join(_repo, "tests", "fixtures", "ssl_key.pem")

if not os.path.exists(_cert):
    print("Cert not found. Generate with: python scripts/generate_fixtures.py")
    sys.exit(1)

with open(_cert, "rb") as f:
    CERT = f.read()
with open(_key, "rb") as f:
    KEY = f.read()


def serve(host: str = "127.0.0.1", port: int = 4433) -> None:
    """Run a minimal QUIC/HTTP3 server with proper timer integration."""

    # --- 1. Socket setup ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.setblocking(False)
    print(f"Listening on {host}:{port} (UDP)")

    # --- 2. QUIC + H3 connection (one connection for simplicity) ---
    config = QuicConfiguration(
        certificate=CERT,
        private_key=KEY,
        idle_timeout=30.0,  # Close after 30s idle
        max_data=1_048_576,  # 1 MB connection-level flow control
        max_stream_data=1_048_576,  # 1 MB per-stream
    )
    quic = QuicConnection(config)
    h3 = H3Connection(sender=quic, is_client=False)

    print("Waiting for QUIC client... (try: curl --http3 -k https://localhost:4433/)")

    peer_addr: tuple[str, int] | None = None

    try:
        while True:
            # --- 3. Timer integration ---
            # get_timer() returns the next deadline (absolute time), or None.
            # Use it as the select() timeout so we wake up at the right time.
            deadline = quic.get_timer()
            timeout = max(0.0, deadline - time.monotonic()) if deadline is not None else 1.0

            # --- 4. Wait for data or timer ---
            readable, _, _ = select.select([sock], [], [], timeout)

            now = time.monotonic()

            if readable:
                # --- 5. Receive datagram -> feed to QUIC ---
                data, addr = sock.recvfrom(65535)
                peer_addr = addr
                events = quic.datagram_received(data, addr, now=now)

                # --- 6. Process QUIC events ---
                for event in events:
                    if isinstance(event, HandshakeComplete):
                        print(f"  Handshake complete with {addr}")

                    elif isinstance(event, StreamDataReceived):
                        # Feed to H3 layer
                        for h3_event in h3.handle_event(event):
                            if isinstance(h3_event, H3HeadersReceived):
                                print(f"  HTTP/3 request on stream {h3_event.stream_id}")
                                # Send response
                                h3.send_headers(
                                    stream_id=h3_event.stream_id,
                                    headers=[
                                        (b":status", b"200"),
                                        (b"content-type", b"text/plain"),
                                    ],
                                    end_stream=False,
                                )
                                h3.send_data(
                                    stream_id=h3_event.stream_id,
                                    data=b"Hello from Zoomies!\n",
                                    end_stream=True,
                                )

                    elif isinstance(event, NewSessionTicket):
                        print(f"  Session ticket issued (lifetime={event.ticket.lifetime}s)")

                    elif isinstance(event, ConnectionClosed):
                        print(f"  Connection closed: {event.reason}")
                        return

                    elif isinstance(event, PacketDropped):
                        print(f"  [debug] Packet dropped: {event.reason}")

            else:
                # --- 7. Timer expired -> handle_timer() ---
                timer_events = quic.handle_timer(now)
                for event in timer_events:
                    if isinstance(event, ConnectionClosed):
                        print(f"  Idle timeout: {event.reason}")
                        return

            # --- 8. Transmit outgoing datagrams ---
            if peer_addr is not None:
                for dgram in quic.send_datagrams():
                    sock.sendto(dgram, peer_addr)

    except KeyboardInterrupt:
        print("\nShutting down...")
        quic.close(reason="server shutdown")
        if peer_addr is not None:
            for dgram in quic.send_datagrams():
                sock.sendto(dgram, peer_addr)
    finally:
        sock.close()


if __name__ == "__main__":
    serve()
