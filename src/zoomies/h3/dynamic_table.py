"""QPACK dynamic table (RFC 9204 §3.2)."""

from __future__ import annotations

# RFC 9204 §3.2.1: entry size = len(name) + len(value) + 32
ENTRY_OVERHEAD = 32


def _entry_size(name: str, value: str) -> int:
    """Byte size of a dynamic table entry per RFC 9204 §3.2.1."""
    return len(name.encode("utf-8")) + len(value.encode("utf-8")) + ENTRY_OVERHEAD


class DynamicTable:
    """QPACK dynamic table with FIFO eviction.

    Entries are stored newest-first: index 0 is the most recently inserted.
    Absolute indices grow monotonically; relative index 0 = newest entry.
    """

    def __init__(self, capacity: int = 0) -> None:
        self._entries: list[tuple[str, str, int]] = []  # (name, value, size)
        self._capacity = capacity
        self._size = 0
        self._insert_count = 0  # absolute index counter

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def size(self) -> int:
        return self._size

    @property
    def insert_count(self) -> int:
        """Total number of entries ever inserted (absolute index counter)."""
        return self._insert_count

    def __len__(self) -> int:
        return len(self._entries)

    def set_capacity(self, capacity: int) -> None:
        """Set table capacity, evicting oldest entries as needed."""
        self._capacity = capacity
        self._evict()

    def insert(self, name: str, value: str) -> int:
        """Insert entry, evicting oldest as needed. Returns absolute index."""
        entry_sz = _entry_size(name, value)
        if entry_sz > self._capacity:
            # Entry too large — evict everything, don't insert (RFC 9204 §3.2.2)
            self._entries.clear()
            self._size = 0
            self._insert_count += 1
            return self._insert_count - 1

        # Evict oldest entries until there's room
        while self._size + entry_sz > self._capacity and self._entries:
            _, _, old_sz = self._entries.pop()
            self._size -= old_sz

        self._entries.insert(0, (name, value, entry_sz))
        self._size += entry_sz
        self._insert_count += 1
        return self._insert_count - 1

    def get(self, relative_index: int) -> tuple[str, str]:
        """Get entry by relative index (0 = newest)."""
        if relative_index < 0 or relative_index >= len(self._entries):
            raise IndexError(f"relative index {relative_index} out of range")
        name, value, _ = self._entries[relative_index]
        return (name, value)

    def get_absolute(self, absolute_index: int) -> tuple[str, str]:
        """Get entry by absolute index."""
        relative = self._insert_count - 1 - absolute_index
        return self.get(relative)

    def relative_to_absolute(self, relative_index: int) -> int:
        """Convert relative index (0=newest) to absolute index."""
        return self._insert_count - 1 - relative_index

    def lookup(self, name: str, value: str) -> tuple[int, bool] | None:
        """Find entry by name+value. Returns (relative_index, exact_match) or None."""
        name_match: int | None = None
        for i, (n, v, _) in enumerate(self._entries):
            if n == name:
                if v == value:
                    return (i, True)
                if name_match is None:
                    name_match = i
        if name_match is not None:
            return (name_match, False)
        return None

    def lookup_absolute(self, name: str, value: str) -> tuple[int, bool] | None:
        """Find entry. Returns (absolute_index, exact_match) or None."""
        result = self.lookup(name, value)
        if result is None:
            return None
        rel_idx, exact = result
        return (self.relative_to_absolute(rel_idx), exact)

    def lookup_name(self, name: str) -> int | None:
        """Find first entry with matching name. Returns relative index or None."""
        for i, (n, _, _) in enumerate(self._entries):
            if n == name:
                return i
        return None

    def lookup_name_absolute(self, name: str) -> int | None:
        """Find first entry with matching name. Returns absolute index or None."""
        rel = self.lookup_name(name)
        if rel is None:
            return None
        return self.relative_to_absolute(rel)

    def _evict(self) -> None:
        """Evict oldest entries until size <= capacity."""
        while self._size > self._capacity and self._entries:
            _, _, old_sz = self._entries.pop()
            self._size -= old_sz
