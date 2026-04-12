"""PATH_CHALLENGE and PATH_RESPONSE frame tests (RFC 9000 §19.17, §19.18)."""

import os

import pytest

from zoomies.encoding import Buffer
from zoomies.frames.path import (
    FRAME_PATH_CHALLENGE,
    FRAME_PATH_RESPONSE,
    PATH_DATA_LEN,
    PathChallengeFrame,
    PathResponseFrame,
    pull_path_challenge,
    pull_path_response,
    push_path_challenge,
    push_path_response,
)


class TestPathChallenge:
    def test_roundtrip(self) -> None:
        data = os.urandom(8)
        buf = Buffer()
        push_path_challenge(buf, data)
        parsed = pull_path_challenge(Buffer(data=buf.data))
        assert parsed.data == data

    def test_bytes_roundtrip(self) -> None:
        """Push then pull yields identical bytes on re-push."""
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        buf = Buffer()
        push_path_challenge(buf, data)
        raw = buf.data
        parsed = pull_path_challenge(Buffer(data=raw))
        buf2 = Buffer()
        push_path_challenge(buf2, parsed.data)
        assert buf2.data == raw

    def test_frame_type_byte(self) -> None:
        data = b"\x00" * 8
        buf = Buffer()
        push_path_challenge(buf, data)
        assert buf.data[0] == FRAME_PATH_CHALLENGE

    def test_wrong_frame_type(self) -> None:
        buf = Buffer(data=bytes([FRAME_PATH_RESPONSE]) + b"\x00" * 8)
        with pytest.raises(ValueError, match="Not a PATH_CHALLENGE"):
            pull_path_challenge(buf)

    def test_wrong_data_length(self) -> None:
        with pytest.raises(ValueError, match="exactly 8 bytes"):
            buf = Buffer()
            push_path_challenge(buf, b"\x00" * 7)

    def test_too_long_data(self) -> None:
        with pytest.raises(ValueError, match="exactly 8 bytes"):
            buf = Buffer()
            push_path_challenge(buf, b"\x00" * 9)

    def test_frozen_dataclass(self) -> None:
        frame = PathChallengeFrame(data=b"\x00" * 8)
        with pytest.raises(AttributeError):
            frame.data = b"\x01" * 8  # type: ignore[misc]


class TestPathResponse:
    def test_roundtrip(self) -> None:
        data = os.urandom(8)
        buf = Buffer()
        push_path_response(buf, data)
        parsed = pull_path_response(Buffer(data=buf.data))
        assert parsed.data == data

    def test_bytes_roundtrip(self) -> None:
        data = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
        buf = Buffer()
        push_path_response(buf, data)
        raw = buf.data
        parsed = pull_path_response(Buffer(data=raw))
        buf2 = Buffer()
        push_path_response(buf2, parsed.data)
        assert buf2.data == raw

    def test_frame_type_byte(self) -> None:
        data = b"\x00" * 8
        buf = Buffer()
        push_path_response(buf, data)
        assert buf.data[0] == FRAME_PATH_RESPONSE

    def test_wrong_frame_type(self) -> None:
        buf = Buffer(data=bytes([FRAME_PATH_CHALLENGE]) + b"\x00" * 8)
        with pytest.raises(ValueError, match="Not a PATH_RESPONSE"):
            pull_path_response(buf)

    def test_wrong_data_length(self) -> None:
        with pytest.raises(ValueError, match="exactly 8 bytes"):
            buf = Buffer()
            push_path_response(buf, b"\x00" * 3)

    def test_frozen_dataclass(self) -> None:
        frame = PathResponseFrame(data=b"\x00" * 8)
        with pytest.raises(AttributeError):
            frame.data = b"\x01" * 8  # type: ignore[misc]


class TestPathChallengeResponseSymmetry:
    """PATH_RESPONSE echoes PATH_CHALLENGE data — same 8 bytes."""

    def test_challenge_data_echoed_in_response(self) -> None:
        challenge_data = os.urandom(8)
        # Serialize challenge
        cbuf = Buffer()
        push_path_challenge(cbuf, challenge_data)
        challenge = pull_path_challenge(Buffer(data=cbuf.data))
        # Serialize response with same data
        rbuf = Buffer()
        push_path_response(rbuf, challenge.data)
        response = pull_path_response(Buffer(data=rbuf.data))
        assert response.data == challenge.data
