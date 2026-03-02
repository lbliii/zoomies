"""Byte pull/push helpers."""

from zoomies.encoding.buffer import Buffer


def pull_bytes(buf: Buffer, n: int) -> bytes:
    """Read n bytes from buffer."""
    return buf.pull_bytes(n)


def push_bytes(buf: Buffer, data: bytes) -> None:
    """Append bytes to buffer."""
    buf.push_bytes(data)
