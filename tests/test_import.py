"""Import and package sanity tests."""


def test_zoomies_imports() -> None:
    """Package imports and exposes __version__."""
    import zoomies

    assert zoomies.__version__ == "0.3.1"


def test_zoomies_events_module() -> None:
    """Events module exposes QUIC event types."""
    from zoomies.events import DatagramReceived, HandshakeComplete

    event = DatagramReceived(data=b"", addr=("127.0.0.1", 443))
    assert event.data == b""
    assert event.addr == ("127.0.0.1", 443)
    assert HandshakeComplete() is not None


def test_zoomies_public_api() -> None:
    """Public API exports from zoomies package."""
    from zoomies import (
        H3Connection,
        H3HeadersReceived,
        HandshakeComplete,
        QuicConfiguration,
        QuicConnection,
        ZeroRttAccepted,
        ZeroRttRejected,
    )

    assert QuicConnection is not None
    assert QuicConfiguration is not None
    assert H3Connection is not None
    assert HandshakeComplete() is not None
    assert H3HeadersReceived(stream_id=0, headers=[], end_stream=True) is not None
    assert ZeroRttAccepted() is not None
    assert ZeroRttRejected() is not None


def test_h3_qpack_exports() -> None:
    """QPACK encoder/decoder exported from zoomies.h3."""
    from zoomies.h3 import QpackDecoder, QpackEncoder

    assert QpackEncoder is not None
    assert QpackDecoder is not None
