"""QPACK encoder/decoder (RFC 9204) -- static table + dynamic table."""

from __future__ import annotations

from dataclasses import dataclass

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint, push_varint
from zoomies.h3.dynamic_table import DynamicTable
from zoomies.h3.qpack_instructions import (
    _pull_prefixed_int,
    _pull_string,
    _push_prefixed_int,
    _push_string,
    encode_insert_literal,
    encode_insert_name_ref,
    encode_set_capacity,
)

# RFC 9204 Appendix A: Static table (subset for MVP)
STATIC_TABLE: list[tuple[str, str]] = [
    (":authority", ""),
    (":path", "/"),
    (":path", "/index.html"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "500"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
]


@dataclass(frozen=True, slots=True)
class Header:
    """HTTP header name-value pair."""

    name: str
    value: str

    def as_bytes(self) -> tuple[bytes, bytes]:
        """Return (name, value) as bytes for H3 events."""
        return (self.name.encode("ascii"), self.value.encode("ascii"))


def _encode_literal(buf: Buffer, name: str, value: str) -> None:
    """Encode literal header (no name reference)."""
    buf.push_uint8(0x20)  # 001 prefix, literal with name
    push_varint(buf, len(name))
    buf.push_bytes(name.encode("utf-8"))
    push_varint(buf, len(value))
    buf.push_bytes(value.encode("utf-8"))


def _decode_literal(buf: Buffer) -> Header:
    """Decode literal header (caller ensures first byte is 0x20)."""
    buf.pull_uint8()  # consume 0x20
    name_len = pull_varint(buf)
    name = buf.pull_bytes(name_len).decode("utf-8")
    value_len = pull_varint(buf)
    value = buf.pull_bytes(value_len).decode("utf-8")
    return Header(name=name, value=value)


def encode_headers(headers: list[Header]) -> bytes:
    """Encode headers to QPACK format (literal for MVP)."""
    buf = Buffer()
    for h in headers:
        idx = _find_static(h.name, h.value)
        if 0 <= idx < 63:
            buf.push_uint8(0xC0 | idx)  # indexed static
        else:
            _encode_literal(buf, h.name, h.value)
    return buf.data


def encode_headers_from_bytes(headers: list[tuple[bytes, bytes]]) -> bytes:
    """Encode headers from bytes (ASGI-compatible) to QPACK format."""
    buf = Buffer()
    for n, v in headers:
        name_str = n.decode("ascii")
        value_str = v.decode("ascii")
        idx = _find_static(name_str, value_str)
        if 0 <= idx < 63:
            buf.push_uint8(0xC0 | idx)
        else:
            buf.push_uint8(0x20)
            push_varint(buf, len(n))
            buf.push_bytes(n)
            push_varint(buf, len(v))
            buf.push_bytes(v)
    return buf.data


def decode_headers(data: bytes) -> list[Header]:
    """Decode QPACK headers (literal and indexed static)."""
    buf = Buffer(data=data)
    result: list[Header] = []
    while not buf.eof():
        first = buf.pull_uint8()
        if (first & 0xC0) == 0xC0:
            idx = first & 0x3F
            if idx < len(STATIC_TABLE):
                n, v = STATIC_TABLE[idx]
                result.append(Header(name=n, value=v))
        elif (first & 0x20) == 0x20:
            buf.seek(buf.tell() - 1)
            result.append(_decode_literal(buf))
    return result


_STATIC_INDEX: dict[tuple[str, str], int] = {
    (n, v): i for i, (n, v) in enumerate(STATIC_TABLE)
}
_STATIC_NAME_INDEX: dict[str, int] = {}
for _i, (_n, _v) in enumerate(STATIC_TABLE):
    if _n not in _STATIC_NAME_INDEX:
        _STATIC_NAME_INDEX[_n] = _i


def _find_static(name: str, value: str) -> int:
    """Find static table index, -1 if not found."""
    return _STATIC_INDEX.get((name, value), -1)


def _find_static_name(name: str) -> int:
    """Find static table index by name only, -1 if not found."""
    return _STATIC_NAME_INDEX.get(name, -1)


# ---------------------------------------------------------------------------
# Stateful QpackEncoder (uses dynamic table)
# ---------------------------------------------------------------------------


class QpackEncoder:
    """QPACK encoder with dynamic table support (RFC 9204).

    Non-blocking mode: Required Insert Count is always 0, so header blocks
    are immediately decodable without waiting for encoder stream processing.
    """

    def __init__(self, max_table_capacity: int = 0) -> None:
        self._table = DynamicTable(capacity=max_table_capacity)
        self._pending_instructions = Buffer()
        self._capacity_set = False

    def set_capacity(self, capacity: int) -> None:
        """Update dynamic table capacity. Emits Set Dynamic Table Capacity."""
        self._table.set_capacity(capacity)
        encode_set_capacity(self._pending_instructions, capacity)
        self._capacity_set = True

    @property
    def table(self) -> DynamicTable:
        return self._table

    def encode(self, headers: list[Header]) -> bytes:
        """Encode a header block.

        Encoding priority:
        1. Static indexed (exact match)
        2. Dynamic indexed (exact match)
        3. Static name ref + literal value (+ insert into dynamic table)
        4. Dynamic name ref + literal value
        5. Full literal (+ insert into dynamic table if capacity allows)

        Returns the encoded header block (without Required Insert Count
        or Delta Base -- we use non-blocking mode so both are 0).
        """
        buf = Buffer()
        # Required Insert Count = 0, Delta Base = 0 (non-blocking)
        _push_prefixed_int(buf, 0x00, 8, 0)  # Required Insert Count
        _push_prefixed_int(buf, 0x00, 7, 0)  # Delta Base (sign=0)

        for h in headers:
            self._encode_header(buf, h.name, h.value)
        return buf.data

    def encode_from_bytes(
        self, headers: list[tuple[bytes, bytes]]
    ) -> bytes:
        """Encode headers from bytes (ASGI-compatible)."""
        buf = Buffer()
        _push_prefixed_int(buf, 0x00, 8, 0)
        _push_prefixed_int(buf, 0x00, 7, 0)

        for n, v in headers:
            self._encode_header(
                buf, n.decode("ascii"), v.decode("ascii")
            )
        return buf.data

    def encoder_stream_data(self) -> bytes:
        """Return pending encoder stream instructions and clear buffer."""
        data = self._pending_instructions.data
        self._pending_instructions = Buffer()
        return data

    def _encode_header(self, buf: Buffer, name: str, value: str) -> None:
        # 1. Static exact match
        static_idx = _find_static(name, value)
        if 0 <= static_idx < 63:
            # Indexed field line (static) -- SS4.5.2
            _push_prefixed_int(buf, 0xC0, 6, static_idx)
            return

        # 2. Dynamic exact match
        dyn_result = self._table.lookup(name, value)
        if dyn_result is not None:
            rel_idx, exact = dyn_result
            if exact:
                # Indexed field line (dynamic) -- SS4.5.2
                # T=0 (dynamic), 6-bit prefix
                _push_prefixed_int(buf, 0x80, 6, rel_idx)
                return

        # 3. Static name ref + literal value
        static_name_idx = _find_static_name(name)
        if static_name_idx >= 0:
            # Literal with name reference (static) -- SS4.5.4
            _push_prefixed_int(buf, 0x50, 4, static_name_idx)
            _push_string(buf, value, prefix_bits=7)
            # Insert into dynamic table
            self._insert_with_static_ref(static_name_idx, value)
            return

        # 4. Dynamic name ref + literal value
        if dyn_result is not None:
            rel_idx, _ = dyn_result
            # Literal with name reference (dynamic) -- SS4.5.4
            # N=0, T=0 (dynamic), 4-bit prefix
            _push_prefixed_int(buf, 0x40, 4, rel_idx)
            _push_string(buf, value, prefix_bits=7)
            # Insert into dynamic table
            self._insert_literal(name, value)
            return

        # 5. Full literal
        # Literal with literal name -- SS4.5.6
        _push_prefixed_int(buf, 0x20, 3, len(name.encode("utf-8")))
        buf.push_bytes(name.encode("utf-8"))
        _push_string(buf, value, prefix_bits=7)
        # Insert into dynamic table
        self._insert_literal(name, value)

    def _insert_with_static_ref(
        self, static_index: int, value: str
    ) -> None:
        if self._table.capacity > 0:
            self._table.insert(STATIC_TABLE[static_index][0], value)
            encode_insert_name_ref(
                self._pending_instructions,
                is_static=True,
                name_index=static_index,
                value=value,
            )

    def _insert_literal(self, name: str, value: str) -> None:
        if self._table.capacity > 0:
            self._table.insert(name, value)
            encode_insert_literal(
                self._pending_instructions, name, value
            )


# ---------------------------------------------------------------------------
# Stateful QpackDecoder (uses dynamic table)
# ---------------------------------------------------------------------------


class QpackDecoder:
    """QPACK decoder with dynamic table support (RFC 9204)."""

    def __init__(self, max_table_capacity: int = 0) -> None:
        self._table = DynamicTable(capacity=max_table_capacity)

    @property
    def table(self) -> DynamicTable:
        return self._table

    def set_capacity(self, capacity: int) -> None:
        self._table.set_capacity(capacity)

    def feed_encoder_stream(self, data: bytes) -> None:
        """Process encoder stream instructions to update dynamic table."""
        from zoomies.h3.qpack_instructions import (
            decode_all_encoder_instructions,
        )

        for itype, fields in decode_all_encoder_instructions(data):
            if itype == "set_capacity":
                self._table.set_capacity(fields["capacity"])
            elif itype == "insert_name_ref":
                if fields["is_static"]:
                    name = STATIC_TABLE[fields["name_index"]][0]
                else:
                    name, _ = self._table.get(fields["name_index"])
                self._table.insert(name, fields["value"])
            elif itype == "insert_literal":
                self._table.insert(fields["name"], fields["value"])
            elif itype == "duplicate":
                name, value = self._table.get(fields["index"])
                self._table.insert(name, value)

    def decode(self, data: bytes) -> list[Header]:
        """Decode a header block with dynamic table support."""
        buf = Buffer(data=data)
        # Required Insert Count
        first = buf.pull_uint8()
        ric = _pull_prefixed_int(buf, first, 8)
        # Delta Base
        first2 = buf.pull_uint8()
        _pull_prefixed_int(buf, first2, 7)

        if ric != 0:
            raise ValueError(
                "Non-zero Required Insert Count not supported "
                "(non-blocking mode only)"
            )

        result: list[Header] = []
        while not buf.eof():
            first = buf.pull_uint8()

            if first & 0x80:
                # Indexed field line -- SS4.5.2
                is_static = bool(first & 0x40)
                idx = _pull_prefixed_int(buf, first, 6)
                if is_static:
                    if idx < len(STATIC_TABLE):
                        n, v = STATIC_TABLE[idx]
                        result.append(Header(name=n, value=v))
                else:
                    n, v = self._table.get(idx)
                    result.append(Header(name=n, value=v))

            elif first & 0x40:
                # Literal with name reference -- SS4.5.4
                is_static = bool(first & 0x10)
                idx = _pull_prefixed_int(buf, first, 4)
                value = _pull_string(buf, prefix_bits=7)
                if is_static:
                    name = STATIC_TABLE[idx][0]
                else:
                    name, _ = self._table.get(idx)
                result.append(Header(name=name, value=value))

            elif first & 0x20:
                # Literal with literal name -- SS4.5.6
                name_len = _pull_prefixed_int(buf, first, 3)
                name = buf.pull_bytes(name_len).decode("utf-8")
                value = _pull_string(buf, prefix_bits=7)
                result.append(Header(name=name, value=value))

        return result
