"""Benchmark: QUIC handshake latency (Initial → Handshake → 1-RTT).

Measures the CPU time for initial key derivation, TLS processing,
and packet encrypt/decrypt during a server-side handshake.

Run with: pytest benchmarks/bench_handshake.py --benchmark-only
"""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.crypto import CryptoPair
from zoomies.encoding import Buffer
from zoomies.frames.crypto import CryptoFrame, push_crypto_frame
from zoomies.packet.builder import push_initial_packet_header

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"
AEAD_TAG_SIZE = 16
PN_SIZE = 4


def _build_client_initial() -> bytes:
    """Build a minimal client Initial packet (just CRYPTO frame with dummy TLS)."""
    crypto = CryptoPair()
    crypto.setup_initial(cid=SERVER_CID, is_client=True)

    payload_buf = Buffer()
    push_crypto_frame(payload_buf, CryptoFrame(offset=0, data=b"\x01" * 200))
    plain_payload = payload_buf.data

    pn = 0
    header_buf = Buffer()
    ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
    push_initial_packet_header(
        header_buf,
        destination_cid=SERVER_CID,
        source_cid=CLIENT_CID,
        token=b"",
        payload_length=ciphertext_len,
    )
    plain_header = header_buf.data
    return crypto.encrypt_packet(plain_header, plain_payload, pn)


def bench_server_initial_processing(benchmark) -> None:
    """Benchmark: server processes a client Initial packet.

    Measures key derivation + decrypt + frame parsing per Initial.
    """
    packet = _build_client_initial()
    addr = ("127.0.0.1", 4433)

    def process_initial():
        config = QuicConfiguration(certificate=CERT, private_key=KEY)
        conn = QuicConnection(config)
        conn.datagram_received(packet, addr, now=1.0)
        return conn

    benchmark(process_initial)


def bench_initial_key_derivation(benchmark) -> None:
    """Benchmark: Initial key derivation from connection ID."""

    def derive():
        crypto = CryptoPair()
        crypto.setup_initial(cid=SERVER_CID, is_client=False)
        return crypto

    benchmark(derive)


def bench_initial_encrypt_decrypt(benchmark) -> None:
    """Benchmark: encrypt then decrypt an Initial packet."""
    client_crypto = CryptoPair()
    client_crypto.setup_initial(cid=SERVER_CID, is_client=True)
    server_crypto = CryptoPair()
    server_crypto.setup_initial(cid=SERVER_CID, is_client=False)

    payload_buf = Buffer()
    push_crypto_frame(payload_buf, CryptoFrame(offset=0, data=b"\x01" * 200))
    plain_payload = payload_buf.data

    header_buf = Buffer()
    ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
    push_initial_packet_header(
        header_buf,
        destination_cid=SERVER_CID,
        source_cid=CLIENT_CID,
        token=b"",
        payload_length=ciphertext_len,
    )
    plain_header = header_buf.data

    def encrypt_decrypt():
        pn = 0
        encrypted = client_crypto.encrypt_packet(plain_header, plain_payload, pn)
        server_crypto.decrypt_packet(encrypted, len(plain_header), pn)

    benchmark(encrypt_decrypt)
