"""NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frames (RFC 9000 19.15, 19.16)."""

from dataclasses import dataclass

from zoomies.encoding import Buffer
from zoomies.primitives.types import CONNECTION_ID_MAX_LEN

FRAME_NEW_CONNECTION_ID = 0x18
FRAME_RETIRE_CONNECTION_ID = 0x19
STATELESS_RESET_TOKEN_LEN = 16


@dataclass(frozen=True, slots=True)
class NewConnectionIdFrame:
    """NEW_CONNECTION_ID — server issues alternative CIDs to client."""

    sequence: int
    retire_prior_to: int
    connection_id: bytes
    stateless_reset_token: bytes


@dataclass(frozen=True, slots=True)
class RetireConnectionIdFrame:
    """RETIRE_CONNECTION_ID — client retires a CID we issued."""

    sequence: int


def pull_retire_connection_id(buf: Buffer) -> RetireConnectionIdFrame:
    """Parse RETIRE_CONNECTION_ID frame (type 0x19)."""
    b = buf.pull_uint8()
    if b != FRAME_RETIRE_CONNECTION_ID:
        raise ValueError("Not a RETIRE_CONNECTION_ID frame")
    sequence = buf.pull_uint_var()
    return RetireConnectionIdFrame(sequence=sequence)


def pull_new_connection_id(buf: Buffer) -> NewConnectionIdFrame:
    """Parse NEW_CONNECTION_ID frame (type 0x18)."""
    b = buf.pull_uint8()
    if b != FRAME_NEW_CONNECTION_ID:
        raise ValueError("Not a NEW_CONNECTION_ID frame")
    sequence = buf.pull_uint_var()
    retire_prior_to = buf.pull_uint_var()
    length = buf.pull_uint8()
    if length > CONNECTION_ID_MAX_LEN:
        raise ValueError(f"Connection ID length {length} exceeds max {CONNECTION_ID_MAX_LEN}")
    connection_id = buf.pull_bytes(length)
    stateless_reset_token = buf.pull_bytes(STATELESS_RESET_TOKEN_LEN)
    return NewConnectionIdFrame(
        sequence=sequence,
        retire_prior_to=retire_prior_to,
        connection_id=connection_id,
        stateless_reset_token=stateless_reset_token,
    )


def push_new_connection_id(
    buf: Buffer,
    sequence: int,
    retire_prior_to: int,
    connection_id: bytes,
    stateless_reset_token: bytes = b"\x00" * STATELESS_RESET_TOKEN_LEN,
) -> None:
    """Serialize NEW_CONNECTION_ID frame."""
    if len(connection_id) > CONNECTION_ID_MAX_LEN:
        raise ValueError(
            f"Connection ID must be 0-{CONNECTION_ID_MAX_LEN} bytes, got {len(connection_id)}"
        )
    if len(stateless_reset_token) != STATELESS_RESET_TOKEN_LEN:
        raise ValueError(f"Stateless reset token must be {STATELESS_RESET_TOKEN_LEN} bytes")
    buf.push_uint8(FRAME_NEW_CONNECTION_ID)
    buf.push_uint_var(sequence)
    buf.push_uint_var(retire_prior_to)
    buf.push_uint8(len(connection_id))
    buf.push_bytes(connection_id)
    buf.push_bytes(stateless_reset_token)
