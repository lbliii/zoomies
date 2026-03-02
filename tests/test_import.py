"""Import and package sanity tests."""


def test_zoomies_imports() -> None:
    """Package imports and exposes __version__."""
    import zoomies

    assert zoomies.__version__ == "0.1.0"


def test_zoomies_events_module() -> None:
    """Events module exposes QUIC event types."""
    from zoomies.events import DatagramReceived, HandshakeComplete

    event = DatagramReceived(data=b"", addr=("127.0.0.1", 443))
    assert event.data == b""
    assert event.addr == ("127.0.0.1", 443)
    assert HandshakeComplete() is not None
