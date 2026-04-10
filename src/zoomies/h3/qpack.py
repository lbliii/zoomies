"""QPACK encoder/decoder (RFC 9204) -- static table + dynamic table."""

from __future__ import annotations

from dataclasses import dataclass

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint, push_varint
from zoomies.h3.dynamic_table import ENTRY_OVERHEAD, DynamicTable
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
# RIC encoding/decoding (RFC 9204 SS4.5.1.1)
# ---------------------------------------------------------------------------


def _max_entries(max_table_capacity: int) -> int:
    """Max entries that can fit in the dynamic table (RFC 9204 SS3.2.2)."""
    return max_table_capacity // ENTRY_OVERHEAD


def _encode_ric(ric: int, max_table_capacity: int) -> int:
    """Encode Required Insert Count for wire format."""
    if ric == 0:
        return 0
    max_ent = _max_entries(max_table_capacity)
    if max_ent == 0:
        return 0
    return (ric % (2 * max_ent)) + 1


def _decode_ric(
    encoded_ric: int,
    max_table_capacity: int,
    total_inserts: int,
) -> int:
    """Decode Required Insert Count from wire format."""
    if encoded_ric == 0:
        return 0
    max_ent = _max_entries(max_table_capacity)
    full_range = 2 * max_ent
    if encoded_ric > full_range:
        raise ValueError("Encoded RIC exceeds full range")
    max_value = total_inserts + max_ent
    max_wrapped = (max_value // full_range) * full_range
    ric = max_wrapped + encoded_ric - 1
    if ric > max_value:
        if ric <= full_range:
            raise ValueError("Invalid RIC")
        ric -= full_range
    if ric == 0:
        raise ValueError("Decoded RIC is zero but encoded was non-zero")
    return ric


# ---------------------------------------------------------------------------
# Stateful QpackEncoder (uses dynamic table)
# ---------------------------------------------------------------------------


class QpackEncoder:
    """QPACK encoder with dynamic table support (RFC 9204).

    References only entries already in the table before encode() is called.
    New entries are inserted after encoding and emitted as encoder stream
    instructions. The decoder must process encoder stream data before
    decoding the header block.
    """

    def __init__(self, max_table_capacity: int = 0) -> None:
        self._table = DynamicTable(capacity=max_table_capacity)
        self._pending_instructions = Buffer()
        self._max_table_capacity = max_table_capacity

    def set_capacity(self, capacity: int) -> None:
        """Update dynamic table capacity. Emits Set Dynamic Table Capacity."""
        self._table.set_capacity(capacity)
        self._max_table_capacity = capacity
        encode_set_capacity(self._pending_instructions, capacity)

    @property
    def table(self) -> DynamicTable:
        return self._table

    def encode(self, headers: list[Header]) -> bytes:
        """Encode a header block.

        Encoding priority:
        1. Static indexed (exact match)
        2. Dynamic indexed (exact match, already in table)
        3. Static name ref + literal value
        4. Dynamic name ref + literal value
        5. Full literal

        New entries are inserted into the dynamic table after encoding.
        """
        return self._do_encode(
            [(h.name, h.value) for h in headers]
        )

    def encode_from_bytes(
        self, headers: list[tuple[bytes, bytes]]
    ) -> bytes:
        """Encode headers from bytes (ASGI-compatible)."""
        return self._do_encode(
            [(n.decode("ascii"), v.decode("ascii")) for n, v in headers]
        )

    def encoder_stream_data(self) -> bytes:
        """Return pending encoder stream instructions and clear buffer."""
        data = self._pending_instructions.data
        self._pending_instructions = Buffer()
        return data

    def _do_encode(self, headers: list[tuple[str, str]]) -> bytes:
        # Snapshot table state — only reference entries < base
        base = self._table.insert_count
        max_ref_abs = -1  # track highest absolute index referenced
        pending_inserts: list[tuple[str, str, int | None]] = []

        header_buf = Buffer()
        for name, value in headers:
            ref_abs = self._encode_header(
                header_buf, name, value, base, pending_inserts
            )
            if ref_abs is not None and ref_abs > max_ref_abs:
                max_ref_abs = ref_abs

        # Compute RIC and Base
        ric = max_ref_abs + 1 if max_ref_abs >= 0 else 0

        # Build prefix: Encoded RIC + Delta Base
        prefix = Buffer()
        encoded_ric = _encode_ric(ric, self._max_table_capacity)
        _push_prefixed_int(prefix, 0x00, 8, encoded_ric)
        # Base = base (insert_count before encoding), Delta = base - ric
        if base >= ric:
            delta_base = base - ric
            _push_prefixed_int(prefix, 0x00, 7, delta_base)  # S=0
        else:
            delta_base = ric - base - 1
            _push_prefixed_int(prefix, 0x80, 7, delta_base)  # S=1

        # Now apply pending inserts (after encoding, so refs are stable)
        for name, value, static_ref in pending_inserts:
            if self._table.capacity > 0:
                self._table.insert(name, value)
                if static_ref is not None:
                    encode_insert_name_ref(
                        self._pending_instructions,
                        is_static=True,
                        name_index=static_ref,
                        value=value,
                    )
                else:
                    encode_insert_literal(
                        self._pending_instructions, name, value
                    )

        return prefix.data + header_buf.data

    def _encode_header(
        self,
        buf: Buffer,
        name: str,
        value: str,
        base: int,
        pending_inserts: list[tuple[str, str, int | None]],
    ) -> int | None:
        """Encode one header. Returns absolute index if dynamic ref used."""
        # 1. Static exact match
        static_idx = _find_static(name, value)
        if 0 <= static_idx < 63:
            _push_prefixed_int(buf, 0xC0, 6, static_idx)
            return None

        # 2. Dynamic exact match (only entries before base)
        dyn_result = self._table.lookup_absolute(name, value)
        if dyn_result is not None:
            abs_idx, exact = dyn_result
            if exact and abs_idx < base:
                # Relative index from base: base - abs_idx - 1
                rel_idx = base - abs_idx - 1
                _push_prefixed_int(buf, 0x80, 6, rel_idx)
                return abs_idx

        # 3. Static name ref + literal value
        static_name_idx = _find_static_name(name)
        if static_name_idx >= 0:
            _push_prefixed_int(buf, 0x50, 4, static_name_idx)
            _push_string(buf, value, prefix_bits=7)
            pending_inserts.append(
                (STATIC_TABLE[static_name_idx][0], value, static_name_idx)
            )
            return None

        # 4. Dynamic name ref + literal value (only entries before base)
        if dyn_result is not None:
            abs_idx, _ = dyn_result
            if abs_idx < base:
                rel_idx = base - abs_idx - 1
                _push_prefixed_int(buf, 0x40, 4, rel_idx)
                _push_string(buf, value, prefix_bits=7)
                pending_inserts.append((name, value, None))
                return abs_idx

        # 5. Full literal
        name_bytes = name.encode("utf-8")
        _push_prefixed_int(buf, 0x20, 3, len(name_bytes))
        buf.push_bytes(name_bytes)
        _push_string(buf, value, prefix_bits=7)
        pending_inserts.append((name, value, None))
        return None


# ---------------------------------------------------------------------------
# Stateful QpackDecoder (uses dynamic table)
# ---------------------------------------------------------------------------


class QpackDecoder:
    """QPACK decoder with dynamic table support (RFC 9204)."""

    def __init__(self, max_table_capacity: int = 0) -> None:
        self._table = DynamicTable(capacity=max_table_capacity)
        self._max_table_capacity = max_table_capacity

    @property
    def table(self) -> DynamicTable:
        return self._table

    def set_capacity(self, capacity: int) -> None:
        self._table.set_capacity(capacity)
        self._max_table_capacity = capacity

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

        # Read Required Insert Count
        first = buf.pull_uint8()
        encoded_ric = _pull_prefixed_int(buf, first, 8)

        # Read Delta Base
        first2 = buf.pull_uint8()
        sign = bool(first2 & 0x80)
        delta_base = _pull_prefixed_int(buf, first2, 7)

        # Decode RIC
        ric = _decode_ric(
            encoded_ric,
            self._max_table_capacity,
            self._table.insert_count,
        )

        # Compute Base
        base = ric + delta_base if not sign else ric - delta_base - 1

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
                    # Dynamic: relative index from base
                    abs_idx = base - idx - 1
                    n, v = self._table.get_absolute(abs_idx)
                    result.append(Header(name=n, value=v))

            elif first & 0x40:
                # Literal with name reference -- SS4.5.4
                is_static = bool(first & 0x10)
                idx = _pull_prefixed_int(buf, first, 4)
                value = _pull_string(buf, prefix_bits=7)
                if is_static:
                    name = STATIC_TABLE[idx][0]
                else:
                    abs_idx = base - idx - 1
                    name, _ = self._table.get_absolute(abs_idx)
                result.append(Header(name=name, value=value))

            elif first & 0x20:
                # Literal with literal name -- SS4.5.6
                name_len = _pull_prefixed_int(buf, first, 3)
                name = buf.pull_bytes(name_len).decode("utf-8")
                value = _pull_string(buf, prefix_bits=7)
                result.append(Header(name=name, value=value))

        return result
