"""Hypothesis property tests for QPACK encoder/decoder."""

from hypothesis import given, settings
from hypothesis import strategies as st

from zoomies.h3.dynamic_table import DynamicTable, _entry_size
from zoomies.h3.qpack import Header, QpackDecoder, QpackEncoder

# Strategy for generating random headers (ASCII-only for QPACK compat)
header_name_st = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz-_",
    min_size=1,
    max_size=20,
)
header_value_st = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789 -_./",
    min_size=0,
    max_size=50,
)
header_st = st.builds(Header, name=header_name_st, value=header_value_st)
headers_st = st.lists(header_st, min_size=1, max_size=10)


@given(headers_list=st.lists(headers_st, min_size=1, max_size=5))
@settings(max_examples=50)
def test_roundtrip_multiple_requests(
    headers_list: list[list[Header]],
) -> None:
    """Encode then decode multiple request header blocks."""
    enc = QpackEncoder(max_table_capacity=4096)
    enc.set_capacity(4096)
    dec = QpackDecoder(max_table_capacity=4096)
    dec.set_capacity(4096)

    for headers in headers_list:
        encoded = enc.encode(headers)
        dec.feed_encoder_stream(enc.encoder_stream_data())
        decoded = dec.decode(encoded)
        assert len(decoded) == len(headers)
        for orig, dec_h in zip(headers, decoded, strict=True):
            assert orig.name == dec_h.name
            assert orig.value == dec_h.value


@given(headers=headers_st)
@settings(max_examples=50)
def test_roundtrip_zero_capacity(headers: list[Header]) -> None:
    """Zero-capacity encoder/decoder round-trips correctly."""
    enc = QpackEncoder(max_table_capacity=0)
    dec = QpackDecoder(max_table_capacity=0)

    encoded = enc.encode(headers)
    decoded = dec.decode(encoded)
    assert len(decoded) == len(headers)
    for orig, dec_h in zip(headers, decoded, strict=True):
        assert orig.name == dec_h.name
        assert orig.value == dec_h.value


@given(
    inserts=st.lists(
        st.tuples(header_name_st, header_value_st),
        min_size=0,
        max_size=50,
    ),
    capacity=st.integers(min_value=32, max_value=512),
)
@settings(max_examples=50)
def test_dynamic_table_size_invariant(inserts: list[tuple[str, str]], capacity: int) -> None:
    """Dynamic table size never exceeds capacity after any insert."""
    table = DynamicTable(capacity=capacity)
    for name, value in inserts:
        if not name:
            continue
        table.insert(name, value)
        assert table.size <= table.capacity


@given(
    inserts=st.lists(
        st.tuples(header_name_st, header_value_st),
        min_size=1,
        max_size=20,
    ),
    capacity=st.integers(min_value=64, max_value=1024),
)
@settings(max_examples=30)
def test_dynamic_table_size_accounting(inserts: list[tuple[str, str]], capacity: int) -> None:
    """Table size equals sum of entry sizes."""
    table = DynamicTable(capacity=capacity)
    for name, value in inserts:
        if not name:
            continue
        table.insert(name, value)

    expected_size = sum(_entry_size(n, v) for n, v, _ in table._entries)
    assert table.size == expected_size
