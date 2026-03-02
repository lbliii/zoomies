"""Tests for test utilities."""

from tests.utils import SERVER_CERTFILE, SERVER_KEYFILE, load


def test_load_fixture() -> None:
    """load() can read fixture files."""
    cert = load("fixtures/ssl_cert.pem")
    assert b"-----BEGIN CERTIFICATE-----" in cert


def test_server_certfile_exists() -> None:
    """SERVER_CERTFILE path points to existing file."""
    import os

    assert os.path.exists(SERVER_CERTFILE)


def test_server_keyfile_exists() -> None:
    """SERVER_KEYFILE path points to existing file."""
    import os

    assert os.path.exists(SERVER_KEYFILE)
