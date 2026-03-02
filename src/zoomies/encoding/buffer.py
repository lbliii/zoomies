"""Buffer — read/write for QUIC packet and frame encoding."""

from typing import Protocol, runtime_checkable

# RFC 9000 variable-length integer max (62 bits)
VARINT_MAX = 0x3FFFFFFFFFFFFFFF


class BufferReadError(ValueError):
    """Raised when reading past end of buffer."""


@runtime_checkable
class BufferLike(Protocol):
    """Protocol for buffer-like objects (for future C-backed impl)."""

    def pull_uint8(self) -> int: ...
    def push_uint8(self, value: int) -> None: ...
    def tell(self) -> int: ...
    def data_slice(self, start: int, end: int) -> bytes: ...


class Buffer:
    """Pure Python buffer for QUIC packet/frame read/write."""

    def __init__(
        self,
        data: bytes | None = None,
        capacity: int = 0,
    ) -> None:
        if data is not None:
            self._data = bytearray(data)
            self._pos = 0
        else:
            self._data = bytearray()
            self._pos = 0

    @property
    def data(self) -> bytes:
        """Current buffer contents (for write mode: all pushed bytes)."""
        return bytes(self._data)

    def tell(self) -> int:
        """Current read/write position."""
        return self._pos

    def seek(self, pos: int) -> None:
        """Set read position."""
        if pos < 0 or pos > len(self._data):
            raise BufferReadError("Seek out of bounds")
        self._pos = pos

    def eof(self) -> bool:
        """True if at end of buffer."""
        return self._pos >= len(self._data)

    def data_slice(self, start: int, end: int) -> bytes:
        """Return slice of buffer without advancing position."""
        return bytes(self._data[start:end])

    def pull_bytes(self, length: int) -> bytes:
        """Read length bytes, advance position."""
        if self._pos + length > len(self._data):
            raise BufferReadError("Read out of bounds")
        result = bytes(self._data[self._pos : self._pos + length])
        self._pos += length
        return result

    def pull_uint8(self) -> int:
        """Read 1 byte as unsigned int."""
        return self.pull_bytes(1)[0]

    def pull_uint16(self) -> int:
        """Read 2 bytes big-endian."""
        b = self.pull_bytes(2)
        return (b[0] << 8) | b[1]

    def pull_uint32(self) -> int:
        """Read 4 bytes big-endian."""
        b = self.pull_bytes(4)
        return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]

    def pull_uint64(self) -> int:
        """Read 8 bytes big-endian."""
        b = self.pull_bytes(8)
        return (
            (b[0] << 56)
            | (b[1] << 48)
            | (b[2] << 40)
            | (b[3] << 32)
            | (b[4] << 24)
            | (b[5] << 16)
            | (b[6] << 8)
            | b[7]
        )

    def push_bytes(self, value: bytes) -> None:
        """Append bytes."""
        self._data.extend(value)
        self._pos = len(self._data)

    def push_uint8(self, value: int) -> None:
        """Append 1 byte."""
        if not 0 <= value <= 0xFF:
            raise ValueError("uint8 must be 0-255")
        self._data.append(value)
        self._pos = len(self._data)

    def push_uint16(self, value: int) -> None:
        """Append 2 bytes big-endian."""
        if not 0 <= value <= 0xFFFF:
            raise ValueError("uint16 must be 0-65535")
        self._data.extend(value.to_bytes(2, "big"))

    def push_uint32(self, value: int) -> None:
        """Append 4 bytes big-endian."""
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("uint32 out of range")
        self._data.extend(value.to_bytes(4, "big"))
        self._pos = len(self._data)

    def push_uint64(self, value: int) -> None:
        """Append 8 bytes big-endian."""
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("uint64 out of range")
        self._data.extend(value.to_bytes(8, "big"))
        self._pos = len(self._data)

    def pull_uint_var(self) -> int:
        """Read variable-length integer (RFC 9000)."""
        from zoomies.encoding.varint import pull_varint

        return pull_varint(self)

    def push_uint_var(self, value: int) -> None:
        """Write variable-length integer (RFC 9000)."""
        from zoomies.encoding.varint import push_varint

        push_varint(self, value)
