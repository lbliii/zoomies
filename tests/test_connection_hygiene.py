"""Phase 1 tests — connection hygiene, timer pattern, flow control, CONNECTION_CLOSE."""

from tests.utils import load
from zoomies.core import QuicConfiguration, QuicConnection
from zoomies.core.connection import ConnectionState
from zoomies.crypto import CryptoPair
from zoomies.encoding import Buffer
from zoomies.events import ConnectionClosed, DecryptionFailed
from zoomies.frames.common import (
    ConnectionCloseFrame,
    pull_connection_close,
    push_connection_close,
)
from zoomies.frames.stream import StreamFrame, push_stream_frame
from zoomies.packet.builder import push_initial_packet_header
from zoomies.primitives import StreamId

CERT = load("fixtures/ssl_cert.pem")
KEY = load("fixtures/ssl_key.pem")
SERVER_CID = b"\x83\x94\xc8\xf0\x3e\x51\x57\x08"
CLIENT_CID = b"\xf0\x67\xa5\x50\x2a\x42\x62\xb5"


def _make_unencrypted_initial() -> bytes:
    """Build unencrypted Initial packet (will fail decrypt)."""
    payload = b"\x00" * 50
    buf = Buffer()
    push_initial_packet_header(
        buf,
        destination_cid=SERVER_CID,
        source_cid=CLIENT_CID,
        token=b"",
        payload_length=len(payload),
    )
    return buf.data + payload


# --- InvalidTag regression tests ---


def test_initial_invalid_tag_no_state_transition() -> None:
    """InvalidTag on Initial decrypt must NOT transition to HANDSHAKE."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    pkt = _make_unencrypted_initial()
    conn.datagram_received(pkt, ("127.0.0.1", 443))
    # State must remain INITIAL (bug fix: was incorrectly going to HANDSHAKE)
    assert conn._state == ConnectionState.INITIAL


def test_initial_invalid_tag_no_response_queued() -> None:
    """InvalidTag on Initial decrypt must NOT queue any response datagrams."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    pkt = _make_unencrypted_initial()
    conn.datagram_received(pkt, ("127.0.0.1", 443))
    assert conn.send_datagrams() == []


def test_initial_invalid_tag_emits_decryption_failed() -> None:
    """InvalidTag on Initial emits DecryptionFailed event."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    pkt = _make_unencrypted_initial()
    events = conn.datagram_received(pkt, ("127.0.0.1", 443))
    df = [e for e in events if isinstance(e, DecryptionFailed)]
    assert len(df) == 1
    assert df[0].packet_type == "initial"


def test_handshake_invalid_tag_emits_decryption_failed() -> None:
    """InvalidTag on Handshake emits DecryptionFailed (not silent pass)."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    # Set up enough state so _handle_handshake runs
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._state = ConnectionState.HANDSHAKE
    conn._handshake_crypto = CryptoPair()
    conn._handshake_crypto.setup_initial(cid=SERVER_CID, is_client=False)

    # Build a Handshake packet with garbage payload (will fail decrypt)
    from zoomies.packet.builder import push_handshake_packet_header

    payload = b"\x00" * 50
    hdr_buf = Buffer()
    push_handshake_packet_header(
        hdr_buf,
        destination_cid=SERVER_CID,
        source_cid=CLIENT_CID,
        payload_length=len(payload),
    )
    pkt = hdr_buf.data + payload
    events = conn.datagram_received(pkt, ("127.0.0.1", 443))
    df = [e for e in events if isinstance(e, DecryptionFailed)]
    assert len(df) == 1
    assert df[0].packet_type == "handshake"


# --- CONNECTION_CLOSE frame tests ---


def test_connection_close_frame_round_trip() -> None:
    """CONNECTION_CLOSE frame serializes and parses correctly."""
    frame = ConnectionCloseFrame(error_code=0x0A, frame_type=0x06, reason_phrase=b"test error")
    buf = Buffer()
    push_connection_close(buf, frame)

    read_buf = Buffer(data=buf.data)
    # Consume frame type byte (0x1C)
    ft = read_buf.pull_uint_var()
    assert ft == 0x1C
    parsed = pull_connection_close(read_buf)
    assert parsed.error_code == 0x0A
    assert parsed.frame_type == 0x06
    assert parsed.reason_phrase == b"test error"


def test_connection_close_frame_empty_reason() -> None:
    """CONNECTION_CLOSE with empty reason round-trips."""
    frame = ConnectionCloseFrame(error_code=0x00)
    buf = Buffer()
    push_connection_close(buf, frame)

    read_buf = Buffer(data=buf.data)
    read_buf.pull_uint_var()  # frame type
    parsed = pull_connection_close(read_buf)
    assert parsed.error_code == 0x00
    assert parsed.reason_phrase == b""


def test_close_method_transitions_to_closed() -> None:
    """close() transitions connection to CLOSED state."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)

    conn.close(error_code=0, reason="done")
    assert conn._state == ConnectionState.CLOSED


def test_close_method_queues_packet() -> None:
    """close() queues a CONNECTION_CLOSE packet."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._address_validated = True

    conn.close(error_code=0x01, reason="protocol error")
    datagrams = conn.send_datagrams()
    assert len(datagrams) >= 1


def test_close_idempotent() -> None:
    """Calling close() twice does not raise or queue duplicate packets."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)

    conn.close()
    conn.close()  # second call is no-op
    assert conn._state == ConnectionState.CLOSED


# --- Timer pattern tests ---


def test_get_timer_returns_none_before_activity() -> None:
    """get_timer() returns None before any datagram received."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    assert conn.get_timer() is None


def test_get_timer_returns_idle_deadline() -> None:
    """get_timer() returns last_activity + idle_timeout after activity."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY, idle_timeout=10.0)
    conn = QuicConnection(config)
    conn._last_activity = 100.0
    conn._state = ConnectionState.ONE_RTT
    assert conn.get_timer() == 110.0


def test_get_timer_returns_none_when_closed() -> None:
    """get_timer() returns None for closed connections."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn._state = ConnectionState.CLOSED
    conn._last_activity = 100.0
    assert conn.get_timer() is None


def test_handle_timer_idle_timeout() -> None:
    """handle_timer() at idle deadline closes connection."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY, idle_timeout=10.0)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._our_cid = SERVER_CID
    conn._peer_cid = CLIENT_CID
    conn._one_rtt_crypto = CryptoPair()
    conn._one_rtt_crypto.setup_initial(cid=SERVER_CID, is_client=False)
    conn._last_activity = 100.0

    events = conn.handle_timer(110.0)
    closed = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(closed) == 1
    assert closed[0].reason == "idle timeout"
    assert conn._state == ConnectionState.CLOSED


def test_handle_timer_before_deadline_no_op() -> None:
    """handle_timer() before deadline returns empty events."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY, idle_timeout=10.0)
    conn = QuicConnection(config)
    conn._state = ConnectionState.ONE_RTT
    conn._last_activity = 100.0

    events = conn.handle_timer(105.0)
    assert events == []
    assert conn._state == ConnectionState.ONE_RTT


def test_datagram_received_updates_last_activity() -> None:
    """datagram_received(now=...) updates _last_activity timestamp."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)
    conn.datagram_received(b"\x00" * 6, ("127.0.0.1", 443), now=42.5)
    assert conn._last_activity == 42.5


# --- Flow control enforcement tests ---


def test_flow_control_violation_closes_connection() -> None:
    """STREAM frame exceeding max_stream_data triggers FLOW_CONTROL_ERROR."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY, max_stream_data=10)
    conn = QuicConnection(config)

    # Build a STREAM frame with 20 bytes at offset 0 (exceeds limit of 10)
    payload_buf = Buffer()
    push_stream_frame(
        payload_buf,
        StreamFrame(
            stream_id=StreamId(0),
            offset=0,
            data=b"x" * 20,
            fin=False,
        ),
    )
    events: list = []
    conn._parse_payload_frames(payload_buf.data, events)
    closed = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(closed) == 1
    assert closed[0].error_code == 0x03


def test_flow_control_within_limit_accepted() -> None:
    """STREAM frame within max_stream_data is accepted normally."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY, max_stream_data=100)
    conn = QuicConnection(config)

    payload_buf = Buffer()
    push_stream_frame(
        payload_buf,
        StreamFrame(
            stream_id=StreamId(0),
            offset=0,
            data=b"hello",
            fin=False,
        ),
    )
    events: list = []
    conn._parse_payload_frames(payload_buf.data, events)
    closed = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(closed) == 0


def test_flow_control_no_limit_always_ok() -> None:
    """When max_stream_data=0 (default), flow control is not enforced."""
    config = QuicConfiguration(certificate=CERT, private_key=KEY)
    conn = QuicConnection(config)

    payload_buf = Buffer()
    push_stream_frame(
        payload_buf,
        StreamFrame(
            stream_id=StreamId(0),
            offset=0,
            data=b"x" * 10000,
            fin=False,
        ),
    )
    events: list = []
    conn._parse_payload_frames(payload_buf.data, events)
    closed = [e for e in events if isinstance(e, ConnectionClosed)]
    assert len(closed) == 0
