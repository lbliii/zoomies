"""Tests for contract keys."""

from zoomies.contracts import connection_key, packet_space_key, stream_key
from zoomies.primitives import ConnectionId, PacketNumberSpace, StreamId


def test_connection_key_deterministic() -> None:
    """Same ConnectionId produces same key."""
    cid = ConnectionId(value=b"abc123")
    assert connection_key(cid) == connection_key(cid)


def test_connection_key_distinct() -> None:
    """Distinct ConnectionIds produce distinct keys."""
    cid1 = ConnectionId(value=b"aaa")
    cid2 = ConnectionId(value=b"bbb")
    assert connection_key(cid1) != connection_key(cid2)


def test_connection_key_hex() -> None:
    """Key is hex of connection ID bytes."""
    cid = ConnectionId(value=b"\x01\x02\x03")
    assert connection_key(cid) == "010203"


def test_stream_key_deterministic() -> None:
    """Same cid+sid produces same key."""
    cid = ConnectionId(value=b"x")
    sid = StreamId(value=1)
    assert stream_key(cid, sid) == stream_key(cid, sid)


def test_stream_key_distinct_by_stream() -> None:
    """Different stream IDs produce distinct keys."""
    cid = ConnectionId(value=b"x")
    assert stream_key(cid, StreamId(value=0)) != stream_key(cid, StreamId(value=1))


def test_stream_key_distinct_by_connection() -> None:
    """Different connection IDs produce distinct keys."""
    sid = StreamId(value=0)
    cid1 = ConnectionId(value=b"a")
    cid2 = ConnectionId(value=b"b")
    assert stream_key(cid1, sid) != stream_key(cid2, sid)


def test_stream_key_format() -> None:
    """Stream key format is connection_key:sid."""
    cid = ConnectionId(value=b"ab")
    sid = StreamId(value=42)
    assert stream_key(cid, sid) == "6162:42"


def test_packet_space_key_deterministic() -> None:
    """Same cid+space produces same key."""
    cid = ConnectionId(value=b"x")
    assert packet_space_key(cid, PacketNumberSpace.INITIAL) == packet_space_key(
        cid, PacketNumberSpace.INITIAL
    )


def test_packet_space_key_distinct() -> None:
    """Different spaces produce distinct keys."""
    cid = ConnectionId(value=b"x")
    k1 = packet_space_key(cid, PacketNumberSpace.INITIAL)
    k2 = packet_space_key(cid, PacketNumberSpace.HANDSHAKE)
    k3 = packet_space_key(cid, PacketNumberSpace.APPLICATION)
    assert k1 != k2 != k3 != k1
