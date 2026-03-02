"""
Minimal H3 server loop (sans-I/O).

Demonstrates the sans-I/O flow (same pattern used by Pounce):
  datagram_received -> events -> handle_event -> build scope
  -> send_headers/send_data -> send_datagrams

Simplified demo: synthetic client Initial with STREAM frame. Real QUIC sends
CRYPTO(ClientHello) first, then STREAM in 1-RTT after TLS. Full flow needs
a real client (e.g. curl --http3).

Run (requires cert/key in tests/fixtures/):
    uv run python -m examples.h3_server_loop

"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zoomies.crypto import CryptoPair
from zoomies.encoding import Buffer
from zoomies.encoding.varint import push_varint
from zoomies.events import H3HeadersReceived, HandshakeComplete
from zoomies.frames.stream import StreamFrame, push_stream_frame
from zoomies.h3 import H3Connection
from zoomies.h3.qpack import Header, encode_headers
from zoomies.primitives import StreamId

# Test fixtures
H3_FRAME_HEADERS = 0x01
SERVER_CID = bytes.fromhex("8394c8f03e515708")
CLIENT_CID = bytes.fromhex("f067a5502a4262b5")


def _make_headers_frame(headers: list[Header]) -> bytes:
    """Build HTTP/3 HEADERS frame."""
    payload = encode_headers(headers)
    buf = Buffer()
    push_varint(buf, H3_FRAME_HEADERS)
    push_varint(buf, len(payload))
    buf.push_bytes(payload)
    return buf.data


def _build_initial_with_h3_request() -> bytes:
    """Build client Initial packet with HTTP/3 GET / request."""
    from zoomies.packet.builder import push_initial_packet_header

    headers = [
        Header(name=":method", value="GET"),
        Header(name=":path", value="/"),
        Header(name=":scheme", value="https"),
        Header(name=":authority", value="localhost"),
    ]
    h3_payload = _make_headers_frame(headers)
    payload_buf = Buffer()
    push_stream_frame(
        payload_buf,
        StreamFrame(
            stream_id=StreamId(0),
            offset=0,
            data=h3_payload,
            fin=True,
        ),
    )
    plain_payload = payload_buf.data
    pn = 0
    pn_bytes = pn.to_bytes(4, "big")
    plain = pn_bytes + plain_payload
    header_buf = Buffer()
    push_initial_packet_header(
        header_buf,
        destination_cid=SERVER_CID,
        source_cid=CLIENT_CID,
        token=b"",
        payload_length=len(plain) + 16,
    )
    plain_header = header_buf.data
    client_crypto = CryptoPair()
    client_crypto.setup_initial(cid=SERVER_CID, is_client=True)
    return client_crypto.encrypt_packet(plain_header, plain_payload, pn)


def main() -> None:
    from zoomies.core import QuicConfiguration, QuicConnection

    _repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cert = os.path.join(_repo, "tests", "fixtures", "ssl_cert.pem")
    key = os.path.join(_repo, "tests", "fixtures", "ssl_key.pem")
    if not os.path.exists(cert):
        print("Run from repo: tests/fixtures/ssl_cert.pem required")
        sys.exit(1)

    with open(cert, "rb") as f:
        CERT = f.read()
    with open(key, "rb") as f:
        KEY = f.read()
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    quic = QuicConnection(config)
    h3 = H3Connection(sender=quic)

    # Synthetic client Initial with HTTP/3 GET /
    packet = _build_initial_with_h3_request()
    addr = ("127.0.0.1", 54321)

    # Sans-I/O loop: datagram_received -> events
    events = quic.datagram_received(packet, addr)

    # handle_event for each QUIC event -> H3 events
    for event in events:
        if isinstance(event, HandshakeComplete):
            print("HandshakeComplete")
        for h3_event in h3.handle_event(event):
            if isinstance(h3_event, H3HeadersReceived):
                # Simplified scope (Pounce builds full ASGI scope)
                stream_id = h3_event.stream_id
                headers = h3_event.headers
                print(f"H3HeadersReceived stream_id={stream_id} headers={len(headers)}")

                # Simulated ASGI response -> send_headers/send_data
                h3.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":status", b"200"),
                        (b"content-type", b"text/plain"),
                    ],
                    end_stream=False,
                )
                h3.send_data(stream_id=stream_id, data=b"Hello, HTTP/3!\n", end_stream=True)

    # transmit = send_datagrams (Pounce: for dg in quic.send_datagrams(): sock.sendto(dg, addr))
    datagrams = quic.send_datagrams()
    print(f"Outgoing datagrams: {len(datagrams)}")
    for i, dg in enumerate(datagrams):
        print(f"  [{i}] {len(dg)} bytes")

    if any(isinstance(e, HandshakeComplete) for e in events) and datagrams:
        print("✓ Sans-I/O loop complete")


if __name__ == "__main__":
    main()
