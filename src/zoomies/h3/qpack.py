"""QPACK encoder/decoder (RFC 9204) — static table, literal headers."""

from dataclasses import dataclass

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint, push_varint

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


_STATIC_INDEX: dict[tuple[str, str], int] = {(n, v): i for i, (n, v) in enumerate(STATIC_TABLE)}


def _find_static(name: str, value: str) -> int:
    """Find static table index, -1 if not found."""
    return _STATIC_INDEX.get((name, value), -1)
