"""
HTTP/3 client + server over loopback — full request/response in one process.

Demonstrates Zoomies' sans-I/O architecture: two QuicConnection instances
(client + server) exchange datagrams in memory. H3Connection sits on top
and handles HTTP/3 framing.

Run from repo root:
    uv run python -m examples.client_server
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import H3DataReceived, H3HeadersReceived
from zoomies.h3 import H3Connection

ADDR = ("127.0.0.1", 4433)

# --- Load TLS certs ---

_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cert = os.path.join(_repo, "tests", "fixtures", "ssl_cert.pem")
_key = os.path.join(_repo, "tests", "fixtures", "ssl_key.pem")

if not os.path.exists(_cert):
    print("Run from repo root: tests/fixtures/ssl_cert.pem required")
    print("Generate with: python scripts/generate_fixtures.py")
    sys.exit(1)

with open(_cert, "rb") as f:
    cert = f.read()
with open(_key, "rb") as f:
    key = f.read()


# --- Helpers ---


def transfer(sender: QuicConnection, receiver: QuicConnection) -> list:
    events = []
    for dg in sender.send_datagrams():
        events.extend(receiver.datagram_received(dg, ADDR))
    return events


def h3_events(quic_events: list, h3: H3Connection) -> list:
    out = []
    for evt in quic_events:
        out.extend(h3.handle_event(evt))
    return out


# --- Create QUIC connections ---

server_quic = QuicConnection(QuicConfiguration(certificate=cert, private_key=key))
client_quic = QuicConnection(QuicConfiguration(is_client=True, verify_mode=False))

h3_client = H3Connection(sender=client_quic)
h3_server = H3Connection(sender=server_quic)

# --- QUIC handshake ---

print("1. QUIC handshake")
client_quic.connect()
transfer(client_quic, server_quic)
transfer(server_quic, client_quic)
transfer(client_quic, server_quic)
transfer(server_quic, client_quic)
print("   Handshake complete")

# --- Client sends HTTP/3 GET request ---

print("2. Client sends: GET /hello")
h3_client.send_headers(
    stream_id=0,
    headers=[
        (b":method", b"GET"),
        (b":path", b"/hello"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
    ],
    end_stream=True,
)

# --- Server receives request ---

server_events = h3_events(transfer(client_quic, server_quic), h3_server)
for evt in server_events:
    if isinstance(evt, H3HeadersReceived):
        headers = dict(evt.headers)
        print(f"   Server received: {headers[b':method'].decode()} {headers[b':path'].decode()}")

# --- Server sends response ---

print("3. Server responds: 200 OK")
h3_server.send_headers(
    stream_id=0,
    headers=[(b":status", b"200"), (b"content-type", b"text/plain")],
    end_stream=False,
)
h3_server.send_data(stream_id=0, data=b"Hello from Zoomies!", end_stream=True)

# --- Client receives response ---

client_events = h3_events(transfer(server_quic, client_quic), h3_client)
for evt in client_events:
    if isinstance(evt, H3HeadersReceived):
        status = dict(evt.headers)[b":status"].decode()
        print(f"   Client received: HTTP/3 {status}")
    elif isinstance(evt, H3DataReceived):
        print(f"   Client received body: {evt.data.decode()}")

# --- Done ---

print("4. Closing connection")
client_quic.close(error_code=0, reason="done")
transfer(client_quic, server_quic)
print("   Done.")
