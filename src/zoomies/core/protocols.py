"""Protocol definitions for QUIC (Pounce integration)."""

from typing import Protocol

from zoomies.events import QuicEvent


class QuicHandler(Protocol):
    """Protocol for handling QUIC events (e.g. from Pounce)."""

    def handle_event(self, event: QuicEvent) -> None: ...
