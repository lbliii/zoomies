"""PATH_CHALLENGE and PATH_RESPONSE frames (RFC 9000 §19.17, §19.18)."""

from dataclasses import dataclass

from zoomies.encoding import Buffer

FRAME_PATH_CHALLENGE = 0x1A
FRAME_PATH_RESPONSE = 0x1B
PATH_DATA_LEN = 8


@dataclass(frozen=True, slots=True)
class PathChallengeFrame:
    """PATH_CHALLENGE — 8 bytes of data for path validation."""

    data: bytes


@dataclass(frozen=True, slots=True)
class PathResponseFrame:
    """PATH_RESPONSE — echoes PATH_CHALLENGE data."""

    data: bytes


def pull_path_challenge(buf: Buffer) -> PathChallengeFrame:
    """Parse PATH_CHALLENGE frame (type 0x1A)."""
    b = buf.pull_uint_var()
    if b != FRAME_PATH_CHALLENGE:
        raise ValueError("Not a PATH_CHALLENGE frame")
    data = buf.pull_bytes(PATH_DATA_LEN)
    return PathChallengeFrame(data=data)


def push_path_challenge(buf: Buffer, data: bytes) -> None:
    """Serialize PATH_CHALLENGE frame."""
    if len(data) != PATH_DATA_LEN:
        raise ValueError(f"PATH_CHALLENGE data must be exactly {PATH_DATA_LEN} bytes")
    buf.push_uint_var(FRAME_PATH_CHALLENGE)
    buf.push_bytes(data)


def pull_path_response(buf: Buffer) -> PathResponseFrame:
    """Parse PATH_RESPONSE frame (type 0x1B)."""
    b = buf.pull_uint_var()
    if b != FRAME_PATH_RESPONSE:
        raise ValueError("Not a PATH_RESPONSE frame")
    data = buf.pull_bytes(PATH_DATA_LEN)
    return PathResponseFrame(data=data)


def push_path_response(buf: Buffer, data: bytes) -> None:
    """Serialize PATH_RESPONSE frame."""
    if len(data) != PATH_DATA_LEN:
        raise ValueError(f"PATH_RESPONSE data must be exactly {PATH_DATA_LEN} bytes")
    buf.push_uint_var(FRAME_PATH_RESPONSE)
    buf.push_bytes(data)
