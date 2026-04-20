"""
Error-flow cheatsheet — how to handle the events agents get wrong most often.

Zoomies surfaces protocol errors as events, never as exceptions. This demo
walks three receive-side error flows back-to-back, printing each event the
caller would pattern-match on:

    1. DecryptionFailed  — garbage datagram arrived. Do NOT reply (RFC 9000
       §8.1 — replying would let an off-path attacker use us as an
       amplifier). Just log and carry on.
    2. PacketDropped     — diagnostic: a datagram was too short to be valid
       QUIC. No state change, no reply. Useful for debugging stalls.
    3. ConnectionClosed  — peer aborted with a non-zero error code. Drain
       any remaining datagrams, then stop. ``error_code`` is the QUIC
       transport error (RFC 9000 §20.1) or an application code.

A fourth (0-RTT rejection) is already covered in
``examples.zero_rtt_resumption``; we don't repeat it here.

Run from repo root:

    uv run python -m examples.error_handling
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoomies import QuicConfiguration, QuicConnection
from zoomies.events import (
    ConnectionClosed,
    DecryptionFailed,
    HandshakeComplete,
    PacketDropped,
    QuicEvent,
)

ADDR = ("127.0.0.1", 4433)

_repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cert_path = os.path.join(_repo, "tests", "fixtures", "ssl_cert.pem")
_key_path = os.path.join(_repo, "tests", "fixtures", "ssl_key.pem")

if not os.path.exists(_cert_path):
    print("Run from repo root: tests/fixtures/ssl_cert.pem required")
    print("Generate with: python scripts/generate_fixtures.py")
    sys.exit(1)

with open(_cert_path, "rb") as f:
    CERT = f.read()
with open(_key_path, "rb") as f:
    KEY = f.read()


def _make_pair() -> tuple[QuicConnection, QuicConnection]:
    server = QuicConnection(QuicConfiguration(certificate=CERT, private_key=KEY))
    client = QuicConnection(
        QuicConfiguration(is_client=True, verify_mode=False, server_name="localhost")
    )
    return client, server


def _transfer(sender: QuicConnection, receiver: QuicConnection) -> list[QuicEvent]:
    events: list[QuicEvent] = []
    for dg in sender.send_datagrams(now=1.0):
        events.extend(receiver.datagram_received(dg, ADDR, now=1.0))
    return events


def _handshake(client: QuicConnection, server: QuicConnection) -> None:
    client.connect()
    _transfer(client, server)
    _transfer(server, client)
    _transfer(client, server)
    _transfer(server, client)


def _label(n: int, title: str) -> None:
    print(f"\n--- {n}. {title} ---")


# ---------------------------------------------------------------------------
# 1. DecryptionFailed — garbage datagram after handshake
# ---------------------------------------------------------------------------

_label(1, "DecryptionFailed (garbage datagram)")

client, server = _make_pair()
_handshake(client, server)

# Forge a short-header packet with the right destination CID but random body.
# This is what an off-path attacker's probe looks like. The library must NOT
# reply — replying lets the attacker amplify traffic at a third party.
garbage = bytes([0x40]) + client._our_cid + os.urandom(50)
pre_reply_queue = len(client.send_datagrams(now=1.0))  # drain any real packets
events = client.datagram_received(garbage, ADDR, now=1.0)
for evt in events:
    match evt:
        case DecryptionFailed(packet_type=pt):
            print(f"   DecryptionFailed(packet_type={pt!r}) — logged, no reply")

# The silence-on-garbage invariant:
assert client.send_datagrams(now=1.0) == [], "must not amplify attacker traffic"
print(f"   Reply queue after garbage: {pre_reply_queue} packets (pre-existing only)")


# ---------------------------------------------------------------------------
# 2. PacketDropped — datagram too short to parse
# ---------------------------------------------------------------------------

_label(2, "PacketDropped (too-short datagram)")

client, server = _make_pair()
_handshake(client, server)

# A stray 3-byte datagram cannot possibly be a valid QUIC packet. The library
# records a diagnostic event but does not disturb connection state.
events = client.datagram_received(b"\x00\x00\x00", ADDR, now=1.0)
for evt in events:
    match evt:
        case PacketDropped(reason=reason):
            print(f"   PacketDropped(reason={reason!r}) — informational")


# ---------------------------------------------------------------------------
# 3. ConnectionClosed — peer aborts with a non-zero error code
# ---------------------------------------------------------------------------

_label(3, "ConnectionClosed (peer abort with error code)")

client, server = _make_pair()
_handshake(client, server)

# PROTOCOL_VIOLATION (RFC 9000 §20.1) = 0x0a. A real peer would send this on
# a protocol-level disagreement; we trigger it here with an explicit close.
server.close(error_code=0x0A, reason="protocol violation: bad frame")
events = _transfer(server, client)
for evt in events:
    match evt:
        case ConnectionClosed(error_code=ec, reason=reason):
            print(f"   ConnectionClosed(error_code=0x{ec:02x}, reason={reason!r})")
            print("   → caller: drain remaining datagrams, then exit the loop")
        case HandshakeComplete():
            pass  # already reported above

# Timer goes quiet — no more work to do.
assert client.get_timer() is None, "closed connection has no pending timers"
print("   client.get_timer() is None — loop can exit cleanly")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print(
    "\nRules of thumb:\n"
    "  • DecryptionFailed → log, DO NOT reply (amplification)\n"
    "  • PacketDropped    → log, no state change\n"
    "  • ConnectionClosed → drain send queue once, then exit\n"
    "  • StreamReset      → stop buffering that stream; trust final_size\n"
    "  • ZeroRttRejected  → resend queued 0-RTT streams as 1-RTT\n"
)
