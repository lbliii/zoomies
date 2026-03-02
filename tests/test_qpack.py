"""QPACK header encode/decode round-trip."""

from hypothesis import given
from hypothesis import strategies as st

from zoomies.h3.qpack import STATIC_TABLE, Header, decode_headers, encode_headers


def test_qpack_literal_roundtrip() -> None:
    """Literal headers round-trip encode/decode."""
    headers = [
        Header(name="x-custom", value="hello"),
        Header(name="content-type", value="application/json"),
    ]
    encoded = encode_headers(headers)
    decoded = decode_headers(encoded)
    assert len(decoded) == 2
    assert decoded[0].name == "x-custom"
    assert decoded[0].value == "hello"
    assert decoded[1].name == "content-type"
    assert decoded[1].value == "application/json"


def test_qpack_static_indexed() -> None:
    """Static table entries encode as indexed."""
    headers = [
        Header(name=":method", value="GET"),
        Header(name=":path", value="/"),
    ]
    encoded = encode_headers(headers)
    decoded = decode_headers(encoded)
    assert decoded[0].name == ":method"
    assert decoded[0].value == "GET"
    assert decoded[1].name == ":path"
    assert decoded[1].value == "/"


def test_qpack_mixed() -> None:
    """Mixed literal and indexed round-trip."""
    headers = [
        Header(name=":method", value="POST"),
        Header(name="x-request-id", value="abc-123"),
    ]
    encoded = encode_headers(headers)
    decoded = decode_headers(encoded)
    assert decoded[0].name == ":method"
    assert decoded[0].value == "POST"
    assert decoded[1].name == "x-request-id"
    assert decoded[1].value == "abc-123"


@given(
    st.lists(
        st.sampled_from([Header(name=n, value=v) for n, v in STATIC_TABLE]),
        min_size=0,
        max_size=20,
    )
)
def test_qpack_roundtrip_property(headers: list[Header]) -> None:
    """decode(encode(headers)) == headers for static-table headers."""
    if not headers:
        return
    encoded = encode_headers(headers)
    decoded = decode_headers(encoded)
    assert len(decoded) == len(headers)
    for d, h in zip(decoded, headers, strict=True):
        assert d.name == h.name
        assert d.value == h.value
