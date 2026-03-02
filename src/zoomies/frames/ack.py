"""ACK frame (RFC 9000 19.3)."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import overload

from zoomies.encoding import Buffer
from zoomies.encoding.varint import pull_varint, push_varint


class RangeSet(Sequence[range]):
    """Set of non-overlapping ranges for ACK blocks."""

    def __init__(self, ranges: list[range] | None = None) -> None:
        self._ranges: list[range] = []
        for r in ranges or []:
            if r.step == 1:
                self.add(r.start, r.stop)
            else:
                raise ValueError("Range must have step 1")

    def add(self, start: int, stop: int | None = None) -> None:
        """Add range [start, stop)."""
        if stop is None:
            stop = start + 1
        if stop <= start:
            raise ValueError("stop must be > start")
        for i, r in enumerate(self._ranges):
            if stop < r.start:
                self._ranges.insert(i, range(start, stop))
                return
            if start > r.stop:
                continue
            start = min(start, r.start)
            stop = max(stop, r.stop)
            while i < len(self._ranges) - 1 and self._ranges[i + 1].start <= stop:
                stop = max(self._ranges[i + 1].stop, stop)
                self._ranges.pop(i + 1)
            self._ranges[i] = range(start, stop)
            return
        self._ranges.append(range(start, stop))

    @overload
    def __getitem__(self, index: int) -> range: ...

    @overload
    def __getitem__(self, index: slice[int] | slice[int | None]) -> Sequence[range]: ...

    def __getitem__(self, index: int | slice[int] | slice[int | None]) -> range | Sequence[range]:
        return self._ranges[index]

    def __len__(self) -> int:
        return len(self._ranges)


@dataclass(frozen=True, slots=True)
class AckFrame:
    """ACK frame — acknowledged packet ranges and delay."""

    ranges: tuple[range, ...]
    delay: int


def pull_ack_frame(buf: Buffer) -> AckFrame:
    """Parse ACK frame from buffer (RFC 9000 19.3)."""
    largest = pull_varint(buf)
    delay = pull_varint(buf)
    ack_range_count = pull_varint(buf)
    first_ack_range = pull_varint(buf)
    rangeset = RangeSet()
    rangeset.add(largest - first_ack_range, largest + 1)
    end = largest - first_ack_range
    for _ in range(ack_range_count):
        gap = pull_varint(buf) + 2
        end -= gap
        ack_range = pull_varint(buf)
        rangeset.add(end - ack_range, end + 1)
        end -= ack_range
    return AckFrame(ranges=tuple(rangeset._ranges), delay=delay)


def push_ack_frame(buf: Buffer, frame: AckFrame) -> None:
    """Serialize ACK frame to buffer."""
    if not frame.ranges:
        raise ValueError("ACK frame must have at least one range")
    rangeset = RangeSet(list(frame.ranges))
    index = len(rangeset) - 1
    r = rangeset[index]
    push_varint(buf, r.stop - 1)
    push_varint(buf, frame.delay)
    push_varint(buf, index)
    push_varint(buf, r.stop - 1 - r.start)
    start = r.start
    while index > 0:
        index -= 1
        r = rangeset[index]
        push_varint(buf, start - r.stop - 1)
        push_varint(buf, r.stop - r.start - 1)
        start = r.start
