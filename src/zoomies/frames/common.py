"""Common frames: PADDING, PING (RFC 9000 19.1, 19.2)."""

from dataclasses import dataclass

from zoomies.encoding import Buffer


@dataclass(frozen=True, slots=True)
class PaddingFrame:
    """PADDING frame — zero or more 0x00 bytes for packet sizing."""

    length: int


@dataclass(frozen=True, slots=True)
class PingFrame:
    """PING frame — liveness check, no fields."""


def pull_padding_frame(buf: Buffer) -> PaddingFrame:
    """Parse PADDING frame: consecutive 0x00 bytes. Returns count."""
    count = 0
    while not buf.eof():
        b = buf.pull_uint8()
        if b != 0:
            buf.seek(buf.tell() - 1)
            break
        count += 1
    return PaddingFrame(length=count)


def push_padding_frame(buf: Buffer, frame: PaddingFrame) -> None:
    """Serialize PADDING frame."""
    for _ in range(frame.length):
        buf.push_uint8(0)


def pull_ping_frame(buf: Buffer) -> PingFrame:
    """Parse PING frame (type 0x01)."""
    b = buf.pull_uint8()
    if b != 0x01:
        raise ValueError("Not a PING frame")
    return PingFrame()


def push_ping_frame(buf: Buffer, _frame: PingFrame) -> None:
    """Serialize PING frame."""
    buf.push_uint8(0x01)
