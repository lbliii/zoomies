"""
Sans-I/O QUIC connection — feed datagrams in, get events and datagrams out.

Demonstrates Zoomies' QuicConnection: the protocol layer consumes bytes
and produces events + outgoing datagrams. The caller owns the socket.

Minimal demo: uses unencrypted payload so decrypt fails; server still queues
Initial response. Full handshake requires a real client (e.g. curl --http3).

Run (requires cert/key in tests/fixtures/):
    python -m examples.sans_io_connection

Or from repo root after uv sync:
    uv run python -m examples.sans_io_connection

"""

import os
import sys

# Add project root for examples
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.encoding import Buffer
from zoomies.events import HandshakeComplete
from zoomies.packet.builder import push_initial_packet_header

# Load certs from tests/fixtures (run from repo root: uv run python -m examples.sans_io_connection)
_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cert = os.path.join(_repo, "tests", "fixtures", "ssl_cert.pem")
_key = os.path.join(_repo, "tests", "fixtures", "ssl_key.pem")

if not os.path.exists(_cert):
    print("Run from repo: tests/fixtures/ssl_cert.pem required")
    print("Generate with: python scripts/generate_fixtures.py")
    sys.exit(1)

with open(_cert, "rb") as f:
    cert = f.read()
with open(_key, "rb") as f:
    key = f.read()

config = QuicConfiguration(certificate=cert, private_key=key)
conn = QuicConnection(config)

# Build minimal client Initial (unencrypted payload for demo)
buf = Buffer()
push_initial_packet_header(
    buf,
    destination_cid=bytes.fromhex("8394c8f03e515708"),
    source_cid=bytes.fromhex("f067a5502a4262b5"),
    token=b"",
    payload_length=50,
)
packet = buf.data + b"\x00" * 50

# Sans-I/O: feed datagram in
events = conn.datagram_received(packet, ("127.0.0.1", 443))
datagrams = conn.send_datagrams()

print("Events:", [type(e).__name__ for e in events])
print("Outgoing datagrams:", len(datagrams))
if any(isinstance(e, HandshakeComplete) for e in events):
    print("✓ HandshakeComplete emitted")
if datagrams:
    print(f"  First datagram: {len(datagrams[0])} bytes")
