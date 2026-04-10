"""Tests for QPACK dynamic table (RFC 9204 §3.2)."""

import pytest

from zoomies.h3.dynamic_table import ENTRY_OVERHEAD, DynamicTable, _entry_size


class TestEntrySize:
    def test_basic(self) -> None:
        assert _entry_size("name", "value") == len(b"name") + len(b"value") + ENTRY_OVERHEAD

    def test_empty(self) -> None:
        assert _entry_size("", "") == ENTRY_OVERHEAD

    def test_utf8(self) -> None:
        # Multi-byte character
        expected = len("héllo".encode()) + len("wörld".encode()) + ENTRY_OVERHEAD
        assert _entry_size("héllo", "wörld") == expected


class TestDynamicTable:
    def test_empty_table(self) -> None:
        t = DynamicTable(capacity=4096)
        assert len(t) == 0
        assert t.size == 0
        assert t.insert_count == 0

    def test_insert_and_get(self) -> None:
        t = DynamicTable(capacity=4096)
        abs_idx = t.insert("x-custom", "hello")
        assert abs_idx == 0
        assert len(t) == 1
        assert t.get(0) == ("x-custom", "hello")

    def test_insert_order(self) -> None:
        """Newest entry is at relative index 0."""
        t = DynamicTable(capacity=4096)
        t.insert("first", "1")
        t.insert("second", "2")
        assert t.get(0) == ("second", "2")
        assert t.get(1) == ("first", "1")

    def test_absolute_index(self) -> None:
        t = DynamicTable(capacity=4096)
        t.insert("a", "1")  # absolute 0
        t.insert("b", "2")  # absolute 1
        assert t.get_absolute(0) == ("a", "1")
        assert t.get_absolute(1) == ("b", "2")

    def test_lookup_exact(self) -> None:
        t = DynamicTable(capacity=4096)
        t.insert("x-custom", "hello")
        result = t.lookup("x-custom", "hello")
        assert result == (0, True)

    def test_lookup_name_only(self) -> None:
        t = DynamicTable(capacity=4096)
        t.insert("x-custom", "hello")
        result = t.lookup("x-custom", "different")
        assert result == (0, False)

    def test_lookup_miss(self) -> None:
        t = DynamicTable(capacity=4096)
        t.insert("x-custom", "hello")
        assert t.lookup("x-other", "hello") is None

    def test_lookup_name(self) -> None:
        t = DynamicTable(capacity=4096)
        t.insert("x-custom", "hello")
        assert t.lookup_name("x-custom") == 0
        assert t.lookup_name("missing") is None

    def test_eviction(self) -> None:
        """Oldest entries evicted when capacity exceeded."""
        entry_sz = _entry_size("key", "val")
        t = DynamicTable(capacity=entry_sz * 2)
        t.insert("key", "val")
        t.insert("key", "val")
        assert len(t) == 2
        # Third insert evicts the oldest
        t.insert("key", "val")
        assert len(t) == 2
        assert t.size <= t.capacity

    def test_set_capacity_evicts(self) -> None:
        t = DynamicTable(capacity=4096)
        t.insert("a", "1")
        t.insert("b", "2")
        assert len(t) == 2
        # Shrink to fit only one entry
        entry_sz = _entry_size("a", "1")
        t.set_capacity(entry_sz)
        assert len(t) == 1
        # Newest survives
        assert t.get(0) == ("b", "2")

    def test_oversized_entry(self) -> None:
        """Entry larger than capacity clears table, doesn't insert."""
        t = DynamicTable(capacity=40)
        t.insert("small", "x")
        assert len(t) == 1
        # This entry is too large (len("toolarge") + len("value") + 32 > 40)
        t.insert("toolarge-name", "toolarge-value")
        assert len(t) == 0
        assert t.size == 0
        # insert_count still increments
        assert t.insert_count == 2

    def test_zero_capacity(self) -> None:
        t = DynamicTable(capacity=0)
        t.insert("a", "b")
        assert len(t) == 0
        assert t.size == 0

    def test_size_invariant(self) -> None:
        """Table size never exceeds capacity after any operation."""
        t = DynamicTable(capacity=200)
        for i in range(100):
            t.insert(f"header-{i}", f"value-{i}")
            assert t.size <= t.capacity

    def test_get_out_of_range(self) -> None:
        t = DynamicTable(capacity=4096)
        with pytest.raises(IndexError):
            t.get(0)
        t.insert("a", "1")
        with pytest.raises(IndexError):
            t.get(1)
        with pytest.raises(IndexError):
            t.get(-1)
