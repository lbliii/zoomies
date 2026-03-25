"""Benchmark: stream data throughput (encrypt/decrypt/parse CPU time).

Measures packet construction, encryption, and stream reassembly throughput
for 1-RTT short header packets carrying STREAM frames.

Run with: pytest benchmarks/bench_throughput.py --benchmark-only
"""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.core.connection import ConnectionState
from zoomies.crypto import CryptoPair
from zoomies.encoding import Buffer
from zoomies.frames.stream import StreamFrame, push_stream_frame
from zoomies.packet.builder import push_short_header
from zoomies.primitives import StreamId

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"
AEAD_TAG_SIZE = 16


def _make_server_conn() -> QuicConnection:
    """Server connection in ONE_RTT state."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True
    return conn


def bench_stream_send_1kb(benchmark) -> None:
    """Benchmark: queue + encrypt 1KB stream data."""
    conn = _make_server_conn()

    data = b"x" * 1024

    def send_1kb():
        conn.send_stream_data(stream_id=0, data=data, end_stream=False)
        return conn.send_datagrams(now=1.0)

    benchmark(send_1kb)


def bench_stream_send_100kb(benchmark) -> None:
    """Benchmark: queue + encrypt 100KB stream data (many packets)."""
    conn = _make_server_conn()

    data = b"x" * 102400

    def send_100kb():
        conn.send_stream_data(stream_id=0, data=data, end_stream=False)
        return conn.send_datagrams(now=1.0)

    benchmark(send_100kb)


def bench_encrypt_short_packet(benchmark) -> None:
    """Benchmark: raw encrypt a short header packet with 1KB payload."""
    crypto = CryptoPair()
    crypto.setup_initial(cid=SERVER_CID, is_client=False)

    payload_buf = Buffer()
    push_stream_frame(
        payload_buf,
        StreamFrame(stream_id=StreamId(0), offset=0, data=b"x" * 1024, fin=False),
    )
    plain_payload = payload_buf.data

    header_buf = Buffer()
    push_short_header(header_buf, CLIENT_CID, 0)
    plain_header = header_buf.data

    def encrypt():
        return crypto.encrypt_packet(plain_header, plain_payload, 0)

    benchmark(encrypt)


def bench_decrypt_short_packet(benchmark) -> None:
    """Benchmark: decrypt a short header packet with 1KB payload."""
    send_crypto = CryptoPair()
    send_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    recv_crypto = CryptoPair()
    recv_crypto.setup_initial(cid=SERVER_CID, is_client=True)

    payload_buf = Buffer()
    push_stream_frame(
        payload_buf,
        StreamFrame(stream_id=StreamId(0), offset=0, data=b"x" * 1024, fin=False),
    )
    plain_payload = payload_buf.data
    header_buf = Buffer()
    push_short_header(header_buf, CLIENT_CID, 0)
    plain_header = header_buf.data

    encrypted = send_crypto.encrypt_packet(plain_header, plain_payload, 0)

    def decrypt():
        return recv_crypto.decrypt_packet(encrypted, len(plain_header), 0)

    benchmark(decrypt)


def bench_stream_reassembly(benchmark) -> None:
    """Benchmark: stream receive reassembly of 100 ordered frames."""
    from zoomies.core.stream import Stream

    def reassemble():
        stream = Stream(StreamId(0))
        for i in range(100):
            offset = i * 100
            frame = StreamFrame(
                stream_id=StreamId(0),
                offset=offset,
                data=b"x" * 100,
                fin=(i == 99),
            )
            stream.add_receive_frame(frame)
        return stream.bytes_delivered

    benchmark(reassemble)
