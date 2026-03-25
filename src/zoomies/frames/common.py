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


@dataclass(frozen=True, slots=True)
class ConnectionCloseFrame:
    """CONNECTION_CLOSE frame (RFC 9000 19.19)."""

    error_code: int
    frame_type: int = 0
    reason_phrase: bytes = b""


def pull_connection_close(buf: Buffer) -> ConnectionCloseFrame:
    """Parse CONNECTION_CLOSE frame (type 0x1C or 0x1D already consumed)."""
    error_code = buf.pull_uint_var()
    frame_type = buf.pull_uint_var()
    reason_len = buf.pull_uint_var()
    reason_phrase = buf.pull_bytes(reason_len) if reason_len > 0 else b""
    return ConnectionCloseFrame(
        error_code=error_code, frame_type=frame_type, reason_phrase=reason_phrase
    )


def push_connection_close(buf: Buffer, frame: ConnectionCloseFrame) -> None:
    """Serialize CONNECTION_CLOSE frame (type 0x1C)."""
    buf.push_uint_var(0x1C)
    buf.push_uint_var(frame.error_code)
    buf.push_uint_var(frame.frame_type)
    buf.push_uint_var(len(frame.reason_phrase))
    if frame.reason_phrase:
        buf.push_bytes(frame.reason_phrase)
