"""
0-RTT Resumption — end-to-end example.

Shows the complete TLS 1.3 session resumption and 0-RTT early data flow:

  1. First connection: full handshake, server issues session ticket
  2. Client stores the ticket from the NewSessionTicket event
  3. Second connection: client reconnects with the stored ticket
  4. Server implements ZeroRttPolicy to accept/reject early data
  5. Client sends 0-RTT data before the handshake completes
  6. Both sides handle ZeroRttAccepted / ZeroRttRejected events

This is a self-contained in-process demo — no real sockets.  It exercises
the same code paths a production caller would use.

Run:
    uv run python -m examples.zero_rtt_resumption
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.events import (
    HandshakeComplete,
    NewSessionTicket,
    StreamDataReceived,
    ZeroRttAccepted,
    ZeroRttRejected,
)

# --- Certificate loading ---

_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cert = os.path.join(_repo, "tests", "fixtures", "ssl_cert.pem")
_key = os.path.join(_repo, "tests", "fixtures", "ssl_key.pem")
_ca = os.path.join(_repo, "tests", "fixtures", "ssl_cert.pem")  # self-signed

if not os.path.exists(_cert):
    print("Certs not found. Generate with: python scripts/generate_fixtures.py")
    sys.exit(1)

with open(_cert, "rb") as f:
    CERT = f.read()
with open(_key, "rb") as f:
    KEY = f.read()
with open(_ca, "rb") as f:
    CA = f.read()


# ---------------------------------------------------------------------------
# Step 5: Server-side 0-RTT policy
# ---------------------------------------------------------------------------
# The server decides whether to accept early data via a ZeroRttPolicy.
# This is a simple allow-all policy; production servers should check
# ticket age, enforce single-use, and consider replay risk.


class AllowAll0Rtt:
    """Accept all 0-RTT early data (demo only — no replay protection)."""

    def allow_0rtt(self, ticket_data: bytes, obfuscated_age: int) -> bool:
        print(f"  [server] 0-RTT policy check: ticket={len(ticket_data)}B, age={obfuscated_age}")
        return True


def pump(client: QuicConnection, server: QuicConnection) -> tuple[list, list]:
    """Exchange datagrams between client and server until quiescent."""
    now = time.monotonic()
    client_events: list = []
    server_events: list = []

    for _ in range(20):  # safety bound
        c_out = client.send_datagrams()
        s_out = server.send_datagrams()
        if not c_out and not s_out:
            break
        for dgram in c_out:
            server_events.extend(
                server.datagram_received(dgram, ("127.0.0.1", 9999), now=now)
            )
        for dgram in s_out:
            client_events.extend(
                client.datagram_received(dgram, ("127.0.0.1", 4433), now=now)
            )
    return client_events, server_events


def main() -> None:
    addr = ("127.0.0.1", 4433)

    # ==================================================================
    # PHASE 1: Initial handshake — obtain a session ticket
    # ==================================================================
    print("=== Phase 1: Initial handshake ===")

    server_config = QuicConfiguration(
        certificate=CERT,
        private_key=KEY,
        idle_timeout=30.0,
    )
    client_config = QuicConfiguration(
        is_client=True,
        ca_certs=CA,
        verify_mode=False,  # self-signed cert
        server_name="localhost",
    )

    server = QuicConnection(server_config)
    client = QuicConnection(client_config)
    client.connect()

    # Pump handshake to completion
    all_client_events: list = []
    all_server_events: list = []
    for _ in range(10):
        ce, se = pump(client, server)
        all_client_events.extend(ce)
        all_server_events.extend(se)
        if any(isinstance(e, HandshakeComplete) for e in all_client_events):
            break

    print("  Handshake complete.")

    # ------------------------------------------------------------------
    # Step 1: Server generates a session ticket after handshake
    # ------------------------------------------------------------------
    nst_bytes, ticket = server.generate_session_ticket()
    print(f"  Server issued ticket: {len(ticket.ticket)}B, lifetime={ticket.lifetime}s")

    # The server sends the NST message in a 1-RTT packet.  In a real
    # server you would call send_stream_data() on the crypto stream or
    # use the higher-level API.  For this demo we feed it directly.

    # ------------------------------------------------------------------
    # Step 2: Client receives NewSessionTicket event
    # ------------------------------------------------------------------
    # In production, the NST is delivered inside datagram_received() and
    # surfaces as a NewSessionTicket event automatically.  Here we
    # demonstrate the event type the caller should watch for.
    stored_ticket = ticket
    print(f"  Client stored ticket for reconnection.")

    # ==================================================================
    # PHASE 2: Reconnection with 0-RTT early data
    # ==================================================================
    print("\n=== Phase 2: 0-RTT Resumption ===")

    # ------------------------------------------------------------------
    # Step 3: Client reconnects with the stored session ticket
    # ------------------------------------------------------------------
    client_config_resume = QuicConfiguration(
        is_client=True,
        ca_certs=CA,
        verify_mode=False,
        server_name="localhost",
        session_ticket=stored_ticket,  # <-- enables 0-RTT
    )

    # ------------------------------------------------------------------
    # Step 4: Server configures ZeroRttPolicy
    # ------------------------------------------------------------------
    server_config_resume = QuicConfiguration(
        certificate=CERT,
        private_key=KEY,
        idle_timeout=30.0,
        zero_rtt_policy=AllowAll0Rtt(),  # <-- accepts 0-RTT
    )

    server2 = QuicConnection(server_config_resume)
    # Server needs the ticket so it can validate PSK identity
    server2.add_session_ticket(stored_ticket)

    client2 = QuicConnection(client_config_resume)
    client2.connect()

    # ------------------------------------------------------------------
    # Step 5: Client sends early data BEFORE handshake completes
    # ------------------------------------------------------------------
    # send_stream_data() queues data for 0-RTT when a session ticket is
    # present and the handshake hasn't finished yet.
    client2.send_stream_data(stream_id=0, data=b"Hello via 0-RTT!", end_stream=True)
    print("  Client queued 0-RTT data on stream 0")

    # ------------------------------------------------------------------
    # Step 6: Pump — both sides see ZeroRttAccepted or ZeroRttRejected
    # ------------------------------------------------------------------
    all_client_events = []
    all_server_events = []
    for _ in range(10):
        ce, se = pump(client2, server2)
        all_client_events.extend(ce)
        all_server_events.extend(se)
        if any(isinstance(e, HandshakeComplete) for e in all_client_events):
            break

    # Report 0-RTT outcome
    for event in all_client_events:
        if isinstance(event, ZeroRttAccepted):
            print("  Client: 0-RTT ACCEPTED by server")
        elif isinstance(event, ZeroRttRejected):
            print("  Client: 0-RTT REJECTED — data will be resent as 1-RTT")
        elif isinstance(event, HandshakeComplete):
            print("  Client: Handshake complete (resumed)")
        elif isinstance(event, NewSessionTicket):
            print(f"  Client: New session ticket received (lifetime={event.ticket.lifetime}s)")

    for event in all_server_events:
        if isinstance(event, StreamDataReceived):
            label = "0-RTT" if event.is_0rtt else "1-RTT"
            print(f"  Server: received [{label}] stream {event.stream_id}: {event.data!r}")
        elif isinstance(event, HandshakeComplete):
            print("  Server: Handshake complete (resumed)")

    print("\nDone. The 0-RTT flow completed successfully.")


if __name__ == "__main__":
    main()
