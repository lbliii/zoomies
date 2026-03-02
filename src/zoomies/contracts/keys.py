"""Canonical key functions for connection and stream lookups.

All caches, indexes, and maps MUST use these. Never use raw str(cid) or
ad-hoc f"{cid}:{sid}" for cross-boundary lookups.
"""

from zoomies.primitives import ConnectionId, PacketNumberSpace, StreamId


def connection_key(cid: ConnectionId) -> str:
    """Canonical key for connection lookups. Use everywhere."""
    return cid.value.hex()


def stream_key(cid: ConnectionId, sid: StreamId) -> str:
    """Canonical key for stream lookups within a connection."""
    return f"{connection_key(cid)}:{sid.value}"


def packet_space_key(cid: ConnectionId, space: PacketNumberSpace) -> str:
    """Key for packet number / crypto state per space (initial, handshake, 1rtt)."""
    return f"{connection_key(cid)}:{space.value}"
