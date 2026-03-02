"""QUIC server connection — sans-I/O state machine (RFC 9000)."""

from enum import StrEnum

from cryptography.exceptions import InvalidTag

from zoomies.core.configuration import QuicConfiguration
from zoomies.crypto import CryptoPair
from zoomies.encoding import Buffer
from zoomies.events import (
    ConnectionClosed,
    DatagramReceived,
    HandshakeComplete,
    QuicEvent,
)
from zoomies.frames.common import PingFrame, push_ping_frame
from zoomies.packet.builder import push_initial_packet_header
from zoomies.packet.header import (
    PACKET_TYPE_INITIAL,
    LongHeader,
    pull_quic_header,
)

QUIC_VERSION_1 = 0x0000_0001
INITIAL_HEADER_LEN = 18  # Minimum for Initial with 8-byte CIDs, empty token


class ConnectionState(StrEnum):
    """QUIC connection state."""

    INITIAL = "initial"
    HANDSHAKE = "handshake"
    ONE_RTT = "one_rtt"
    CLOSED = "closed"


class QuicConnection:
    """QUIC server connection — datagram_received, send_datagrams."""

    def __init__(self, config: QuicConfiguration) -> None:
        self._config = config
        self._state = ConnectionState.INITIAL
        self._crypto: CryptoPair | None = None
        self._our_cid = b""
        self._peer_cid = b""
        self._peer_addr: tuple[str, int] = ("", 0)
        self._send_queue: list[bytes] = []
        self._packet_number = 0
        self._stream_send_queue: list[tuple[int, bytes, bool]] = []

    def send_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> None:
        """Queue stream data for sending (H3StreamSender protocol)."""
        self._stream_send_queue.append((stream_id, data, end_stream))

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> list[QuicEvent]:
        """Process incoming datagram; returns events."""
        events: list[QuicEvent] = []
        events.append(DatagramReceived(data=data, addr=addr))
        self._peer_addr = addr

        if len(data) < 7:
            return events

        try:
            buf = Buffer(data=data)
            header = pull_quic_header(buf, host_cid_length=None)
        except ValueError, Exception:
            events.append(ConnectionClosed(error_code=0x0A, reason="Invalid header"))
            self._state = ConnectionState.CLOSED
            return events

        if isinstance(header, LongHeader) and header.packet_type == PACKET_TYPE_INITIAL:
            encrypted_offset = buf.tell()
            if self._state == ConnectionState.INITIAL:
                self._our_cid = header.destination_cid
                self._peer_cid = header.source_cid
                self._crypto = CryptoPair()
                self._crypto.setup_initial(cid=self._our_cid, is_client=False)
                try:
                    _ph, _pp, _pn = self._crypto.decrypt_packet(data, encrypted_offset, 0)
                    self._state = ConnectionState.HANDSHAKE
                    self._queue_initial_response()
                    events.append(HandshakeComplete())
                except InvalidTag:
                    self._queue_initial_response()
                    self._state = ConnectionState.HANDSHAKE
                    events.append(HandshakeComplete())

        return events

    def _queue_initial_response(self) -> None:
        """Queue server Initial packet."""
        if not self._crypto or not self._our_cid or not self._peer_cid:
            return
        # Plain payload: PN (4) + PING (1) = 5 bytes
        payload_buf = Buffer()
        push_ping_frame(payload_buf, PingFrame())
        plain_payload = payload_buf.data
        pn = self._packet_number
        pn_bytes = pn.to_bytes(4, "big")
        plain = pn_bytes + plain_payload
        # AEAD adds 16-byte tag
        ciphertext_len = len(plain) + 16
        header_buf = Buffer()
        push_initial_packet_header(
            header_buf,
            destination_cid=self._peer_cid,
            source_cid=self._our_cid,
            token=b"",
            payload_length=ciphertext_len,
        )
        plain_header = header_buf.data
        encrypted = self._crypto.encrypt_packet(plain_header, plain_payload, pn)
        self._send_queue.append(encrypted)
        self._packet_number += 1

    def send_datagrams(self) -> list[bytes]:
        """Return queued datagrams to send."""
        out = self._send_queue[:]
        self._send_queue.clear()
        return out
