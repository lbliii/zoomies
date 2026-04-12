"""QUIC connection — sans-I/O state machine (RFC 9000).

Supports both client and server roles. Set QuicConfiguration.is_client=True for client mode.
"""

import bisect
import os
from enum import StrEnum

from cryptography.exceptions import InvalidTag

from zoomies.core.configuration import QuicConfiguration
from zoomies.core.stream import Stream
from zoomies.crypto import CryptoPair, QuicClientTlsContext, QuicTlsContext
from zoomies.crypto.tls import ClientTlsState, SessionTicket
from zoomies.encoding import Buffer
from zoomies.events import (
    ConnectionClosed,
    ConnectionIdIssued,
    ConnectionIdRetired,
    ConnectionMigrated,
    DatagramReceived,
    DecryptionFailed,
    HandshakeComplete,
    QuicEvent,
    RetryReceived,
    StopSendingReceived,
    StreamDataReceived,
    StreamReset,
    ZeroRttAccepted,
    ZeroRttRejected,
)
from zoomies.frames.ack import AckFrame, RangeSet, pull_ack_frame, push_ack_frame
from zoomies.frames.common import (
    ConnectionCloseFrame,
    PingFrame,
    pull_connection_close,
    pull_padding_frame,
    pull_ping_frame,
    push_connection_close,
    push_ping_frame,
)
from zoomies.frames.connection_id import (
    pull_new_connection_id,
    pull_retire_connection_id,
    push_new_connection_id,
)
from zoomies.frames.crypto import CryptoFrame, pull_crypto_frame, push_crypto_frame
from zoomies.frames.path import (
    pull_path_challenge,
    pull_path_response,
    push_path_challenge,
    push_path_response,
)
from zoomies.frames.stream import (
    StreamFrame,
    pull_reset_stream_frame,
    pull_stop_sending_frame,
    pull_stream_frame,
    push_stream_frame,
)
from zoomies.packet.builder import (
    push_handshake_packet_header,
    push_initial_packet_header,
    push_short_header,
    push_zero_rtt_packet_header,
)
from zoomies.packet.header import (
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_RETRY,
    PACKET_TYPE_ZERO_RTT,
    LongHeader,
    ShortHeader,
    pull_quic_header,
)
from zoomies.packet.retry import encode_quic_retry, get_retry_integrity_tag
from zoomies.primitives import StreamId
from zoomies.recovery import (
    CongestionController,
    PacketSpace,
    RttEstimator,
    SentAckFrame,
    SentCryptoFrame,
    SentHandshakeDoneFrame,
    SentNewConnectionIdFrame,
    SentPacket,
    SentPathChallengeFrame,
    SentPathResponseFrame,
    SentPingFrame,
    SentStreamFrame,
    detect_lost_packets,
)

INITIAL_HEADER_LEN = 18
CRYPTO_FRAME_TYPE = 0x06
HANDSHAKE_DONE_FRAME_TYPE = 0x1E
MTU = 1200
AEAD_TAG_SIZE = 16
PN_SIZE = 4


class ConnectionState(StrEnum):
    """QUIC connection state."""

    INITIAL = "initial"
    HANDSHAKE = "handshake"
    ONE_RTT = "one_rtt"
    CLOSED = "closed"


def _merge_crypto_ranges(ranges: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
    """Merge overlapping/adjacent (offset, data) ranges."""
    if not ranges:
        return []
    sorted_ranges = sorted(ranges, key=lambda r: r[0])
    merged: list[tuple[int, bytes]] = [sorted_ranges[0]]
    for start, data in sorted_ranges[1:]:
        prev_start, prev_data = merged[-1]
        prev_end = prev_start + len(prev_data)
        if start <= prev_end:
            overlap = prev_end - start
            if overlap < len(data):
                merged[-1] = (prev_start, prev_data + data[overlap:])
        else:
            merged.append((start, data))
    return merged


class QuicConnection:
    """QUIC connection — datagram_received, send_datagrams.

    Supports both client and server roles via config.is_client.
    """

    def __init__(self, config: QuicConfiguration) -> None:
        self._config = config
        self._is_client = config.is_client
        self._state = ConnectionState.INITIAL
        self._initial_crypto: CryptoPair | None = None
        self._handshake_crypto: CryptoPair | None = None
        self._zero_rtt_crypto: CryptoPair | None = None
        self._one_rtt_crypto: CryptoPair | None = None
        self._tls_ctx: QuicTlsContext | None = None
        self._client_tls_ctx: QuicClientTlsContext | None = None
        self._our_cid = b""
        self._peer_cid = b""
        self._peer_addr: tuple[str, int] = ("", 0)
        self._send_queue: list[bytes] = []
        self._initial_pn = 0
        self._handshake_pn = 0
        self._one_rtt_pn = 0
        # Receive packet number tracking (expected next PN per level)
        self._initial_recv_pn = 0
        self._handshake_recv_pn = 0
        self._one_rtt_recv_pn = 0
        self._stream_send_queue: list[tuple[int, bytes, bool]] = []
        self._zero_rtt_stream_queue: list[tuple[int, bytes, bool]] = []
        self._zero_rtt_accepted: bool | None = None  # None=unknown, True/False after EE
        # Separate CRYPTO buffers per encryption level (RFC 9000 §19.6)
        self._initial_crypto_recv: list[tuple[int, bytes]] = []
        self._initial_crypto_fed = 0
        self._handshake_crypto_recv: list[tuple[int, bytes]] = []
        self._handshake_crypto_fed = 0
        self._our_cids: set[bytes] = set()
        self._our_seq_to_cid: dict[int, bytes] = {}
        self._next_cid_sequence = 0
        # Peer CIDs received via NEW_CONNECTION_ID
        self._peer_cids: dict[int, bytes] = {}  # seq → cid
        self._active_connection_id_limit = 2  # RFC 9000 §18.2 minimum
        # Stream state for reassembly and offset tracking
        self._streams: dict[int, Stream] = {}
        # ACK tracking — received packet numbers per space
        self._initial_ack_ranges = RangeSet()
        self._handshake_ack_ranges = RangeSet()
        self._application_ack_ranges = RangeSet()
        self._ack_needed_initial = False
        self._ack_needed_handshake = False
        self._ack_needed_application = False
        # Timer tracking (sans-I/O: caller provides timestamps)
        self._last_activity: float = 0.0
        self._now: float = 0.0  # current timestamp for packet recording
        # Recovery: sent packet tracking and RTT estimation (RFC 9002)
        self._initial_space = PacketSpace()
        self._handshake_space = PacketSpace()
        self._application_space = PacketSpace()
        self._rtt = RttEstimator()
        self._cc = CongestionController()
        self._pto_count = 0
        # Anti-amplification (RFC 9000 §8): limit response before address validation
        self._bytes_received = 0
        self._bytes_sent = 0
        # Client is never subject to anti-amplification limits
        self._address_validated = config.is_client
        # Session tickets for PSK resumption (server-side)
        self._session_tickets: list = []
        # Retry state
        self._original_destination_cid: bytes | None = None  # ODCID for Retry flow
        self._retry_source_cid: bytes | None = None  # CID from Retry packet
        self._retry_sent = False  # Server: have we sent a Retry?
        self._retry_received = False  # Client: have we received a Retry?
        self._client_hello_bytes: bytes | None = None  # Cached for Retry resend
        # Retransmission queues for lost frames
        self._crypto_retransmit: list[tuple[int, bytes]] = []  # (offset, data)
        self._handshake_done_pending = False
        self._probe_needed = False
        # Path validation (RFC 9000 §9)
        self._pending_path_challenge: bytes | None = None  # challenge we sent, awaiting response
        self._migrating_addr: tuple[str, int] | None = None  # addr being validated
        self._peer_disable_active_migration: bool = False  # peer's transport param
        self._datagram_addr: tuple[str, int] = ("", 0)  # addr of current datagram

    @property
    def our_cid(self) -> bytes:
        """Our connection ID (server's CID). Set after first Initial packet."""
        return self._our_cid

    @property
    def our_cids(self) -> tuple[bytes, ...]:
        """All active connection IDs we've issued (for CID-based routing)."""
        return tuple(self._our_cids)

    def _get_or_create_stream(self, stream_id: StreamId) -> Stream:
        """Get or create a stream by ID."""
        sid = stream_id.value
        if sid not in self._streams:
            stream = Stream(stream_id)
            if self._config.max_stream_data > 0:
                stream.set_max_stream_data(self._config.max_stream_data)
            self._streams[sid] = stream
        return self._streams[sid]

    def add_session_ticket(self, ticket: SessionTicket) -> None:
        """Register a session ticket for PSK validation on future connections (server)."""
        self._session_tickets.append(ticket)
        if self._tls_ctx is not None:
            self._tls_ctx.add_session_ticket(ticket)

    def connect(self) -> None:
        """Generate Initial packet with ClientHello. Client mode only. Call once."""
        if not self._is_client:
            raise RuntimeError("connect() is only for client mode")
        self._our_cid = os.urandom(8)
        self._our_cids = {self._our_cid}
        self._our_seq_to_cid = {0: self._our_cid}
        self._next_cid_sequence = 1
        # Client picks a random destination CID for the Initial packet
        self._peer_cid = os.urandom(8)
        # Initial keys derived from destination CID (RFC 9001 §5.2)
        self._initial_crypto = CryptoPair()
        self._initial_crypto.setup_initial(cid=self._peer_cid, is_client=True)
        self._client_tls_ctx = QuicClientTlsContext(
            ca_certs=self._config.ca_certs,
            verify_mode=self._config.verify_mode,
            server_name=self._config.server_name,
            session_ticket=self._config.session_ticket,
        )
        client_hello = self._client_tls_ctx.build_client_hello()
        self._client_hello_bytes = client_hello  # Cache for potential Retry resend
        self._queue_initial_client_hello(client_hello)
        # Set up 0-RTT crypto if we have a session ticket for early data
        if self._config.session_ticket is not None:
            from cryptography.hazmat.primitives import hashes

            psk = self._config.session_ticket.derive_psk()
            from zoomies.crypto._hkdf import hkdf_extract

            early_secret = hkdf_extract(hashes.SHA256, bytes(32), psk)
            ch_hash = self._client_tls_ctx._client_hello_hash
            if ch_hash is not None:
                self._zero_rtt_crypto = CryptoPair()
                self._zero_rtt_crypto.setup_0rtt(early_secret, ch_hash, is_client=True)

    def _queue_initial_client_hello(self, client_hello: bytes) -> None:
        """Queue Initial packet containing ClientHello CRYPTO frame."""
        self._queue_initial_client_hello_packet(client_hello, token=b"")

    def _queue_initial_client_hello_packet(self, client_hello: bytes, token: bytes) -> None:
        """Queue an Initial packet containing the client's ClientHello."""
        if not self._initial_crypto:
            return
        payload_buf = Buffer()
        push_crypto_frame(payload_buf, CryptoFrame(offset=0, data=client_hello))
        # Build header first to get its actual size for padding calculation
        pn = self._initial_pn
        # Use a dummy payload length to measure header size (varint length is stable)
        probe_buf = Buffer()
        push_initial_packet_header(
            probe_buf,
            destination_cid=self._peer_cid,
            source_cid=self._our_cid,
            token=token,
            payload_length=1200,  # dummy — just for header size measurement
        )
        header_len = len(probe_buf.data)
        # Pad with PADDING frames to meet 1200-byte minimum (RFC 9000 §14.1)
        min_payload = MTU - header_len - PN_SIZE - AEAD_TAG_SIZE
        if len(payload_buf.data) < min_payload:
            payload_buf.push_bytes(b"\x00" * (min_payload - len(payload_buf.data)))
        plain_payload = payload_buf.data
        header_buf = Buffer()
        ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
        push_initial_packet_header(
            header_buf,
            destination_cid=self._peer_cid,
            source_cid=self._our_cid,
            token=token,
            payload_length=ciphertext_len,
        )
        plain_header = header_buf.data
        encrypted = self._initial_crypto.encrypt_packet(plain_header, plain_payload, pn)
        self._send_queue.append(encrypted)
        self._initial_space.on_packet_sent(
            packet_number=pn,
            sent_time=self._now,
            sent_bytes=len(encrypted),
            ack_eliciting=True,
            in_flight=True,
            frames=(SentCryptoFrame(offset=0, length=len(client_hello)),),
        )
        self._initial_pn += 1

    def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        """Queue stream data for sending (H3StreamSender protocol).

        If 0-RTT crypto is available and handshake hasn't completed,
        data is queued for 0-RTT transmission.
        """
        if (
            self._is_client
            and self._zero_rtt_crypto is not None
            and self._state != ConnectionState.ONE_RTT
            and self._zero_rtt_accepted is None
        ):
            self._zero_rtt_stream_queue.append((stream_id, data, end_stream))
        else:
            self._stream_send_queue.append((stream_id, data, end_stream))

    def datagram_received(
        self, data: bytes, addr: tuple[str, int], *, now: float = 0.0
    ) -> list[QuicEvent]:
        """Process incoming datagram; returns events."""
        events: list[QuicEvent] = []
        events.append(DatagramReceived(data=data, addr=addr))
        self._now = now
        self._bytes_received += len(data)
        self._datagram_addr = addr  # stash for post-decrypt migration check

        # During handshake, accept addr unconditionally
        if self._state in (ConnectionState.INITIAL, ConnectionState.HANDSHAKE):
            self._peer_addr = addr
        if now > 0.0:
            self._last_activity = now

        if len(data) < 7:
            return events

        try:
            buf = Buffer(data=data)
            cid_len = len(self._our_cid) if self._our_cid else None
            header = pull_quic_header(buf, host_cid_length=cid_len)
        except ValueError:
            events.append(ConnectionClosed(error_code=0x0A, reason="Invalid header"))
            self._state = ConnectionState.CLOSED
            return events

        if isinstance(header, LongHeader):
            if header.packet_type == PACKET_TYPE_INITIAL:
                self._handle_initial(data, buf, header, events)
            elif header.packet_type == PACKET_TYPE_HANDSHAKE:
                self._handle_handshake(data, buf, header, events)
            elif header.packet_type == PACKET_TYPE_ZERO_RTT:
                self._handle_0rtt(data, buf, header, events)
            elif header.packet_type == PACKET_TYPE_RETRY:
                self._handle_retry(header, events)
        elif isinstance(header, ShortHeader):
            self._handle_short(data, buf, header, events)

        return events

    def _handle_initial(
        self, data: bytes, buf: Buffer, header: LongHeader, events: list[QuicEvent]
    ) -> None:
        """Handle Initial packet (server receives ClientHello, client receives ServerHello)."""
        encrypted_offset = buf.tell()

        if self._is_client:
            self._handle_initial_client(data, encrypted_offset, header, events)
        else:
            self._handle_initial_server(data, encrypted_offset, header, events)

    def _handle_initial_server(
        self,
        data: bytes,
        encrypted_offset: int,
        header: LongHeader,
        events: list[QuicEvent],
    ) -> None:
        """Server: handle Initial packet containing ClientHello."""
        handler = self._config.retry_token_handler

        if self._state == ConnectionState.INITIAL:
            # Retry flow: if handler is configured and no token, send Retry
            if handler is not None and not header.token and not self._retry_sent:
                self._send_retry(header)
                return

            # Retry flow: if handler is configured and token present, validate
            if handler is not None and header.token:
                odcid = handler.validate_token(header.token, self._peer_addr)
                if odcid is None:
                    # Invalid token — drop packet silently
                    return
                self._original_destination_cid = odcid
                self._address_validated = True

            self._our_cid = header.destination_cid
            self._our_cids = {self._our_cid}
            self._our_seq_to_cid = {0: self._our_cid}
            self._next_cid_sequence = 1
            self._peer_cid = header.source_cid
            self._initial_crypto = CryptoPair()
            self._initial_crypto.setup_initial(cid=self._our_cid, is_client=False)
            self._tls_ctx = QuicTlsContext(
                certificate=self._config.certificate,
                private_key=self._config.private_key,
            )
            for ticket in self._session_tickets:
                self._tls_ctx.add_session_ticket(ticket)
            if self._config.zero_rtt_policy is not None:
                self._tls_ctx.accept_early_data = self._check_zero_rtt_policy()

        if not self._initial_crypto:
            return

        try:
            _ph, plain_payload, pn = self._initial_crypto.decrypt_packet(
                data, encrypted_offset, self._initial_recv_pn
            )
            self._initial_recv_pn = pn + 1
            self._initial_ack_ranges.add(pn)
            self._ack_needed_initial = True
            self._state = ConnectionState.HANDSHAKE
            self._queue_initial_response(now=self._now)
            self._parse_payload_frames(plain_payload, events, crypto_level="initial")
            self._feed_crypto_to_tls(events, level="initial")
        except InvalidTag:
            events.append(DecryptionFailed(packet_type="initial"))

    def _send_retry(self, header: LongHeader) -> None:
        """Server: send Retry packet to validate client address."""
        handler = self._config.retry_token_handler
        if handler is None:
            return

        original_dcid = header.destination_cid
        token = handler.generate_token(original_dcid, self._peer_addr)

        # Generate a new CID for the Retry packet
        retry_scid = os.urandom(8)
        self._retry_source_cid = retry_scid
        self._original_destination_cid = original_dcid

        from zoomies.primitives.types import QUIC_VERSION_1

        retry_packet = encode_quic_retry(
            version=QUIC_VERSION_1,
            source_cid=retry_scid,
            destination_cid=header.source_cid,
            original_destination_cid=original_dcid,
            retry_token=token,
        )
        self._send_queue.append(retry_packet)
        self._retry_sent = True

    def _handle_initial_client(
        self,
        data: bytes,
        encrypted_offset: int,
        header: LongHeader,
        events: list[QuicEvent],
    ) -> None:
        """Client: handle server's Initial packet (ServerHello in CRYPTO)."""
        if not self._initial_crypto:
            return
        # Server may use a different source CID than what we sent to
        if self._state == ConnectionState.INITIAL:
            self._peer_cid = header.source_cid

        try:
            _ph, plain_payload, pn = self._initial_crypto.decrypt_packet(
                data, encrypted_offset, self._initial_recv_pn
            )
            self._initial_recv_pn = pn + 1
            self._initial_ack_ranges.add(pn)
            self._ack_needed_initial = True
            self._state = ConnectionState.HANDSHAKE
            self._parse_payload_frames(plain_payload, events, crypto_level="initial")
            self._feed_crypto_to_tls(events, level="initial")
        except InvalidTag:
            events.append(DecryptionFailed(packet_type="initial"))

    def _handle_retry(self, header: LongHeader, events: list[QuicEvent]) -> None:
        """Client: handle Retry packet from server."""
        if not self._is_client:
            return
        # RFC 9000 §17.2.5.2: client MUST accept only one Retry per connection
        if self._retry_received:
            return
        if self._state != ConnectionState.INITIAL:
            return

        # Validate integrity tag (RFC 9001 §5.8)
        # Reconstruct packet-without-tag from header fields
        first_byte = 0xC0 | (3 << 4)
        packet_without_tag = (
            bytes([first_byte])
            + header.version.to_bytes(4, "big")
            + bytes([len(header.destination_cid)])
            + header.destination_cid
            + bytes([len(header.source_cid)])
            + header.source_cid
            + header.token
        )
        expected_tag = get_retry_integrity_tag(packet_without_tag, self._peer_cid, header.version)
        if header.integrity_tag != expected_tag:
            # Invalid integrity tag — drop silently
            return

        self._retry_received = True
        # Store the original destination CID (what we sent in the first Initial)
        self._original_destination_cid = self._peer_cid
        # The Retry packet's source CID becomes our new destination CID
        self._peer_cid = header.source_cid
        self._retry_source_cid = header.source_cid

        # Reset Initial crypto with new destination CID
        self._initial_crypto = CryptoPair()
        self._initial_crypto.setup_initial(cid=self._peer_cid, is_client=True)
        self._initial_pn = 0
        self._initial_recv_pn = 0
        self._initial_ack_ranges = RangeSet()

        # Discard 0-RTT state — Retry invalidates early data (RFC 9000 §8.1.4)
        self._zero_rtt_crypto = None
        self._zero_rtt_stream_queue = []

        # Re-send Initial with the Retry token using cached ClientHello
        if self._client_hello_bytes is not None:
            self._queue_initial_client_hello_with_token(self._client_hello_bytes, header.token)

        events.append(RetryReceived(retry_source_cid=header.source_cid))

    def _queue_initial_client_hello_with_token(self, client_hello: bytes, token: bytes) -> None:
        """Queue Initial packet with Retry token containing ClientHello."""
        self._queue_initial_client_hello_packet(client_hello, token)

    def _handle_0rtt(
        self, data: bytes, buf: Buffer, header: LongHeader, events: list[QuicEvent]
    ) -> None:
        """Server: handle 0-RTT packet containing early data."""
        if self._is_client or not self._zero_rtt_crypto:
            return
        encrypted_offset = buf.tell()
        try:
            _ph, plain_payload, pn = self._zero_rtt_crypto.decrypt_packet(
                data, encrypted_offset, self._one_rtt_recv_pn
            )
            # 0-RTT shares Application packet number space (RFC 9002 §A.3)
            self._one_rtt_recv_pn = pn + 1
            self._application_ack_ranges.add(pn)
            self._ack_needed_application = True
            self._parse_payload_frames(plain_payload, events, is_0rtt=True)
        except InvalidTag:
            events.append(DecryptionFailed(packet_type="0rtt"))

    def _handle_handshake(
        self, data: bytes, buf: Buffer, header: LongHeader, events: list[QuicEvent]
    ) -> None:
        """Handle Handshake packet."""
        if not self._handshake_crypto:
            return
        encrypted_offset = buf.tell()
        try:
            _ph, plain_payload, pn = self._handshake_crypto.decrypt_packet(
                data, encrypted_offset, self._handshake_recv_pn
            )
            self._handshake_recv_pn = pn + 1
            self._handshake_ack_ranges.add(pn)
            self._ack_needed_handshake = True
            self._parse_payload_frames(plain_payload, events, crypto_level="handshake")
            self._feed_crypto_to_tls(events, level="handshake")
        except InvalidTag:
            events.append(DecryptionFailed(packet_type="handshake"))

    def _handle_short(
        self, data: bytes, buf: Buffer, header: ShortHeader, events: list[QuicEvent]
    ) -> None:
        """Handle Short header (1-RTT)."""
        # Client may receive 1-RTT packets (with HANDSHAKE_DONE) while still in HANDSHAKE state
        if not self._one_rtt_crypto:
            return
        if self._state not in (ConnectionState.ONE_RTT, ConnectionState.HANDSHAKE):
            return
        encrypted_offset = buf.tell()
        try:
            _ph, plain_payload, pn = self._one_rtt_crypto.decrypt_packet(
                data, encrypted_offset, self._one_rtt_recv_pn
            )
            self._one_rtt_recv_pn = pn + 1
            self._application_ack_ranges.add(pn)
            self._ack_needed_application = True
            # Migration detection AFTER successful decryption (RFC 9000 §9):
            # Only authenticated packets can trigger path validation.
            addr = self._datagram_addr
            if (
                addr != self._peer_addr
                and addr != self._migrating_addr
                and not self._peer_disable_active_migration
            ):
                self._migrating_addr = addr
                self._send_path_challenge(addr)
            self._parse_payload_frames(plain_payload, events, datagram_addr=addr)
        except InvalidTag:
            events.append(DecryptionFailed(packet_type="1rtt"))

    def _feed_crypto_to_tls(self, events: list[QuicEvent], *, level: str = "initial") -> None:
        """Feed contiguous CRYPTO data to TLS, queue Handshake packets."""
        # Select the correct CRYPTO buffer for this encryption level
        if level == "initial":
            crypto_recv = self._initial_crypto_recv
            crypto_fed = self._initial_crypto_fed
        else:
            crypto_recv = self._handshake_crypto_recv
            crypto_fed = self._handshake_crypto_fed

        merged = _merge_crypto_ranges(crypto_recv)
        parts: list[bytes] = []
        new_fed = crypto_fed
        for start, data in merged:
            if start <= new_fed:
                end = start + len(data)
                if end > new_fed:
                    parts.append(data[new_fed - start :])
                    new_fed = end
            else:
                break

        # Update the correct fed counter
        if level == "initial":
            self._initial_crypto_fed = new_fed
            self._initial_crypto_recv = [
                (s, d) for s, d in self._initial_crypto_recv if s + len(d) > new_fed
            ]
        else:
            self._handshake_crypto_fed = new_fed
            self._handshake_crypto_recv = [
                (s, d) for s, d in self._handshake_crypto_recv if s + len(d) > new_fed
            ]

        if not parts:
            return
        to_feed = b"".join(parts)

        if self._is_client:
            self._feed_crypto_to_client_tls(to_feed, events)
        else:
            self._feed_crypto_to_server_tls(to_feed, events)

    def _handle_zero_rtt_rejected(self, events: list[QuicEvent]) -> None:
        """Handle 0-RTT rejection: resend all 0-RTT stream data as 1-RTT."""
        self._zero_rtt_accepted = False
        events.append(ZeroRttRejected())
        # Move any unsent 0-RTT data to the 1-RTT queue
        if self._zero_rtt_stream_queue:
            self._stream_send_queue.extend(self._zero_rtt_stream_queue)
            self._zero_rtt_stream_queue = []
        # Re-queue data that was already sent as 0-RTT for resend as 1-RTT
        resend_streams: set[int] = set()
        for pkt in list(self._application_space.sent_packets.values()):
            for frame in pkt.frames:
                if isinstance(frame, SentStreamFrame):
                    stream = self._get_or_create_stream(StreamId(frame.stream_id))
                    data = stream._send.get_data(frame.offset, frame.length)
                    if data:
                        self._stream_send_queue.append((frame.stream_id, data, frame.fin))
                        resend_streams.add(frame.stream_id)
        # Reset stream send state so 1-RTT resend starts from offset 0
        for sid in resend_streams:
            stream = self._get_or_create_stream(StreamId(sid))
            stream._send.reset_for_0rtt_rejection()
        # Reset Application PN space. Resetting to PN 0 is safe here because the
        # server rejected 0-RTT — it never derived 0-RTT keys, so it never observed
        # any 0-RTT packet numbers. Both sides agree 1-RTT starts at PN 0.
        self._one_rtt_pn = 0
        self._application_space = PacketSpace()
        # Discard 0-RTT crypto — no longer needed
        self._zero_rtt_crypto = None

    def _check_zero_rtt_policy(
        self, ticket_data: bytes | None = None, obfuscated_age: int = 0
    ) -> bool:
        """Check if 0-RTT is allowed by the configured policy. Default: reject."""
        policy = self._config.zero_rtt_policy
        if policy is None:
            return False
        return policy.allow_0rtt(ticket_data=ticket_data or b"", obfuscated_age=obfuscated_age)

    def _feed_crypto_to_server_tls(self, data: bytes, events: list[QuicEvent]) -> None:
        """Server: feed CRYPTO data to server TLS context."""
        if not self._tls_ctx:
            return
        result = self._tls_ctx.receive(data)
        if result.handshake_secret and not self._handshake_crypto:
            self._handshake_crypto = CryptoPair()
            self._handshake_crypto.setup_handshake(result.handshake_secret, is_client=False)
        # Set up 0-RTT decryption if PSK accepted and policy allows
        if (
            result.is_psk
            and result.early_secret is not None
            and result.client_hello_hash is not None
            and self._zero_rtt_crypto is None
            and self._check_zero_rtt_policy(result.psk_ticket_data, result.psk_obfuscated_age)
        ):
            self._zero_rtt_crypto = CryptoPair()
            self._zero_rtt_crypto.setup_0rtt(
                result.early_secret, result.client_hello_hash, is_client=False
            )
        if result.data_to_send:
            # Split TLS data: ServerHello goes in Initial CRYPTO, rest in Handshake CRYPTO
            # ServerHello is the first message (type 0x02)
            tls_data = result.data_to_send
            if tls_data and tls_data[0] == 0x02:
                sh_len = 4 + int.from_bytes(tls_data[1:4], "big")
                server_hello = tls_data[:sh_len]
                handshake_data = tls_data[sh_len:]
                self._queue_initial_crypto_response(server_hello)
                if handshake_data:
                    self._queue_handshake_response(handshake_data)
            else:
                self._queue_handshake_response(tls_data)
        if result.traffic_secret and not self._one_rtt_crypto:
            self._one_rtt_crypto = CryptoPair()
            self._one_rtt_crypto.setup_1rtt(result.traffic_secret, is_client=False)
            self._state = ConnectionState.ONE_RTT
            self._address_validated = True
            events.append(HandshakeComplete())
            self._issue_cid_pool(events)
            self._queue_handshake_done()

    def _feed_crypto_to_client_tls(self, data: bytes, events: list[QuicEvent]) -> None:
        """Client: feed CRYPTO data to client TLS context."""
        if not self._client_tls_ctx:
            return
        result = self._client_tls_ctx.receive(data)
        if result.handshake_secret and not self._handshake_crypto:
            self._handshake_crypto = CryptoPair()
            self._handshake_crypto.setup_handshake(result.handshake_secret, is_client=True)
        # Check 0-RTT acceptance/rejection after EE is processed
        # Only check once the client TLS state has moved past WAIT_ENCRYPTED_EXTENSIONS
        ee_processed = self._client_tls_ctx.state not in (
            ClientTlsState.START,
            ClientTlsState.WAIT_SERVER_HELLO,
            ClientTlsState.WAIT_ENCRYPTED_EXTENSIONS,
        )
        if self._zero_rtt_crypto is not None and self._zero_rtt_accepted is None and ee_processed:
            if result.early_data_accepted:
                self._zero_rtt_accepted = True
                events.append(ZeroRttAccepted())
            else:
                self._handle_zero_rtt_rejected(events)
        if result.data_to_send:
            # Client Finished — send in Handshake packet
            self._queue_handshake_response(result.data_to_send)
        if result.traffic_secret and not self._one_rtt_crypto:
            self._one_rtt_crypto = CryptoPair()
            self._one_rtt_crypto.setup_1rtt(result.traffic_secret, is_client=True)
            # Client doesn't emit HandshakeComplete yet — wait for HANDSHAKE_DONE

    def _parse_payload_frames(
        self,
        payload: bytes,
        events: list[QuicEvent],
        *,
        is_0rtt: bool = False,
        datagram_addr: tuple[str, int] | None = None,
        crypto_level: str = "initial",
    ) -> None:
        """Parse QUIC frames from decrypted payload; collect CRYPTO for TLS."""
        buf = Buffer(data=payload)
        while not buf.eof():
            try:
                pos = buf.tell()
                first = buf.pull_uint_var()
                buf.seek(pos)
                if first == 0x00:
                    pull_padding_frame(buf)
                elif first == 0x01:
                    pull_ping_frame(buf)
                elif first in (0x02, 0x03):
                    buf.pull_uint8()
                    ack = pull_ack_frame(buf)
                    self._process_ack(ack)
                elif first == 0x04:
                    frame = pull_reset_stream_frame(buf)
                    events.append(
                        StreamReset(
                            stream_id=frame.stream_id.value,
                            error_code=frame.error_code,
                            final_size=frame.final_size,
                        )
                    )
                elif first == 0x05:
                    frame = pull_stop_sending_frame(buf)
                    events.append(
                        StopSendingReceived(
                            stream_id=frame.stream_id.value,
                            error_code=frame.error_code,
                        )
                    )
                elif first == CRYPTO_FRAME_TYPE:
                    frame = pull_crypto_frame(buf)
                    if crypto_level == "initial":
                        bisect.insort(self._initial_crypto_recv, (frame.offset, frame.data))
                    else:
                        bisect.insort(self._handshake_crypto_recv, (frame.offset, frame.data))
                elif first == 0x18:
                    frame = pull_new_connection_id(buf)
                    self._peer_cids[frame.sequence] = frame.connection_id
                    # Retire peer CIDs with sequence < retire_prior_to
                    for seq in list(self._peer_cids):
                        if seq < frame.retire_prior_to:
                            del self._peer_cids[seq]
                elif first == 0x19:
                    frame = pull_retire_connection_id(buf)
                    cid = self._our_seq_to_cid.pop(frame.sequence, None)
                    if cid is not None:
                        self._our_cids.discard(cid)
                        events.append(ConnectionIdRetired(connection_id=cid))
                        # Issue replacement CID to maintain pool
                        self._queue_new_connection_id(events)
                elif first == 0x1A:
                    frame = pull_path_challenge(buf)
                    self._queue_path_response(frame.data)
                elif first == 0x1B:
                    frame = pull_path_response(buf)
                    self._handle_path_response(frame.data, events, datagram_addr)
                elif first in (0x1C, 0x1D):
                    buf.pull_uint_var()  # consume frame type
                    frame = pull_connection_close(buf)
                    self._state = ConnectionState.CLOSED
                    events.append(
                        ConnectionClosed(
                            error_code=frame.error_code,
                            reason=frame.reason_phrase.decode("utf-8", errors="replace"),
                        )
                    )
                    return
                elif first == HANDSHAKE_DONE_FRAME_TYPE:
                    buf.pull_uint_var()  # consume frame type
                    if self._is_client and self._one_rtt_crypto:
                        self._state = ConnectionState.ONE_RTT
                        events.append(HandshakeComplete())
                elif 0x08 <= first <= 0x0F:
                    frame = pull_stream_frame(buf)
                    stream = self._get_or_create_stream(frame.stream_id)
                    if not stream._recv.flow_control_ok(frame.offset, len(frame.data)):
                        self._close_with_error(0x03, "Flow control limit exceeded", events)
                        return
                    delivered = stream.add_receive_frame(frame)
                    if delivered or frame.fin:
                        events.append(
                            StreamDataReceived(
                                stream_id=frame.stream_id.value,
                                data=delivered,
                                end_stream=stream.receive_complete,
                                is_0rtt=is_0rtt,
                            )
                        )
                else:
                    break
            except ValueError:
                break

    def _process_ack(self, ack: AckFrame) -> None:
        """Process received ACK frame — update RTT, detect loss, retransmit."""
        ack_ranges = list(ack.ranges)
        # Determine which space this ACK is for based on connection state
        if self._state == ConnectionState.HANDSHAKE:
            space = self._initial_space
        elif self._state == ConnectionState.ONE_RTT:
            space = self._application_space
        else:
            return

        newly_acked = space.on_ack_received(ack_ranges)
        if not newly_acked:
            return

        # Congestion control: process ACKed packets
        self._cc.on_packets_acked(newly_acked)

        # RTT sample from the largest newly-acked packet
        largest = max(newly_acked, key=lambda p: p.packet_number)
        if largest.sent_time > 0.0 and self._now > 0.0:
            latest_rtt = self._now - largest.sent_time
            if latest_rtt > 0.0:
                # Convert ACK delay from microseconds to seconds
                ack_delay = ack.delay / 1_000_000.0
                self._rtt.update(
                    latest_rtt=latest_rtt,
                    ack_delay=ack_delay,
                    handshake_confirmed=self._state == ConnectionState.ONE_RTT,
                )
                self._pto_count = 0

        # Loss detection (RFC 9002 §6)
        lost = detect_lost_packets(
            space.sent_packets, space.largest_acked_packet, self._now, self._rtt
        )
        if lost:
            self._cc.on_packets_lost(lost, self._now)
            self._retransmit_lost(lost)

    def _retransmit_lost(self, lost: list[SentPacket]) -> None:
        """Re-queue retransmittable frames from lost packets."""
        for pkt in lost:
            for frame in pkt.frames:
                if isinstance(frame, SentCryptoFrame):
                    self._crypto_retransmit.append(
                        (frame.offset, b"")  # CRYPTO data tracked by TLS layer
                    )
                elif isinstance(frame, SentStreamFrame):
                    # Retrieve original data from stream send buffer
                    stream = self._get_or_create_stream(StreamId(frame.stream_id))
                    data = stream._send.get_data(frame.offset, frame.length)
                    if data:
                        self._stream_send_queue.append((frame.stream_id, data, frame.fin))
                elif isinstance(frame, SentHandshakeDoneFrame):
                    self._handshake_done_pending = True
                # SentAckFrame: NOT retransmitted (RFC 9002)
                # SentPingFrame: NOT retransmitted
                # SentNewConnectionIdFrame: NOT retransmitted (idempotent)

    def _queue_new_connection_id(self, events: list[QuicEvent], retire_prior_to: int = 0) -> None:
        """Queue 1-RTT packet with NEW_CONNECTION_ID for connection migration."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return
        new_cid = os.urandom(8)
        sequence = self._next_cid_sequence
        self._next_cid_sequence += 1
        self._our_seq_to_cid[sequence] = new_cid
        self._our_cids.add(new_cid)
        events.append(ConnectionIdIssued(connection_id=new_cid, retire_prior_to=retire_prior_to))
        payload_buf = Buffer()
        push_new_connection_id(
            payload_buf,
            sequence=sequence,
            retire_prior_to=retire_prior_to,
            connection_id=new_cid,
        )
        self._queue_one_rtt_control_packet(
            payload_buf.data,
            (SentNewConnectionIdFrame(sequence=sequence),),
        )

    def _issue_cid_pool(self, events: list[QuicEvent]) -> None:
        """Issue CIDs up to active_connection_id_limit (RFC 9000 §5.1.1)."""
        # _our_cid (seq 0) is always in the pool. Issue additional CIDs.
        while len(self._our_cids) < self._active_connection_id_limit:
            self._queue_new_connection_id(events)

    def _queue_path_response(self, challenge_data: bytes) -> None:
        """Queue PATH_RESPONSE echoing the challenge data (RFC 9000 §8.2.2)."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return
        payload_buf = Buffer()
        push_path_response(payload_buf, challenge_data)
        self._queue_one_rtt_control_packet(
            payload_buf.data,
            (SentPathResponseFrame(data=challenge_data),),
        )

    def _send_path_challenge(self, addr: tuple[str, int]) -> None:
        """Send PATH_CHALLENGE to validate a new peer address (RFC 9000 §8.2)."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return
        challenge_data = os.urandom(8)
        self._pending_path_challenge = challenge_data
        payload_buf = Buffer()
        push_path_challenge(payload_buf, challenge_data)
        self._queue_one_rtt_control_packet(
            payload_buf.data,
            (SentPathChallengeFrame(data=challenge_data),),
        )

    def _handle_path_response(
        self, data: bytes, events: list[QuicEvent], datagram_addr: tuple[str, int] | None = None
    ) -> None:
        """Handle incoming PATH_RESPONSE — completes migration if challenge matches.

        Only completes migration if the response arrived from the address being
        validated (RFC 9000 §8.2.2), proving reachability on the new path.
        """
        if self._pending_path_challenge is not None and data == self._pending_path_challenge:
            old_addr = self._peer_addr
            new_addr = self._migrating_addr
            # Verify response came from the address we're validating
            if datagram_addr is not None and new_addr is not None and datagram_addr != new_addr:
                return  # response from wrong address — don't complete migration
            self._pending_path_challenge = None
            if new_addr is not None:
                self._peer_addr = new_addr
                self._migrating_addr = None
                # Reset congestion state for new path (RFC 9000 §9.4)
                self._cc = CongestionController()
                self._rtt = RttEstimator()
                events.append(ConnectionMigrated(old_addr=old_addr, new_addr=new_addr))
                # Issue new CID with advanced retire_prior_to (linkability prevention)
                self._queue_new_connection_id(events, retire_prior_to=self._next_cid_sequence - 1)

    def _queue_handshake_done(self) -> None:
        """Queue HANDSHAKE_DONE frame in a 1-RTT packet (RFC 9000 19.20)."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return
        payload_buf = Buffer()
        payload_buf.push_uint_var(HANDSHAKE_DONE_FRAME_TYPE)
        self._queue_one_rtt_control_packet(payload_buf.data, (SentHandshakeDoneFrame(),))

    def _queue_one_rtt_control_packet(
        self,
        plain_payload: bytes,
        frames: tuple[
            SentHandshakeDoneFrame
            | SentNewConnectionIdFrame
            | SentPathChallengeFrame
            | SentPathResponseFrame,
            ...,
        ],
    ) -> None:
        """Queue a single 1-RTT control packet and track it in application space."""
        self._send_queue.append(self._encrypt_short_packet(plain_payload, frames))

    def _queue_initial_crypto_response(self, tls_data: bytes) -> None:
        """Queue Initial packet with CRYPTO frame (e.g., ServerHello)."""
        if not self._initial_crypto or not self._our_cid or not self._peer_cid:
            return
        payload_buf = Buffer()
        push_crypto_frame(payload_buf, CryptoFrame(offset=0, data=tls_data))
        plain_payload = payload_buf.data
        pn = self._initial_pn
        header_buf = Buffer()
        ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
        push_initial_packet_header(
            header_buf,
            destination_cid=self._peer_cid,
            source_cid=self._our_cid,
            token=b"",
            payload_length=ciphertext_len,
        )
        plain_header = header_buf.data
        encrypted = self._initial_crypto.encrypt_packet(plain_header, plain_payload, pn)
        self._send_queue.append(encrypted)
        self._initial_space.on_packet_sent(
            packet_number=pn,
            sent_time=self._now,
            sent_bytes=len(encrypted),
            ack_eliciting=True,
            in_flight=True,
            frames=(SentCryptoFrame(offset=0, length=len(tls_data)),),
        )
        self._initial_pn += 1

    def _queue_initial_response(self, now: float = 0.0) -> None:
        """Queue server Initial packet."""
        if not self._initial_crypto or not self._our_cid or not self._peer_cid:
            return
        payload_buf = Buffer()
        frames: list[SentAckFrame | SentPingFrame] = []
        # Include ACK if we have received Initial packets
        if len(self._initial_ack_ranges) > 0:
            ack = AckFrame(ranges=tuple(self._initial_ack_ranges._ranges), delay=0)
            buf_type = Buffer()
            buf_type.push_uint_var(0x02)  # ACK frame type
            payload_buf.push_bytes(buf_type.data)
            push_ack_frame(payload_buf, ack)
            self._ack_needed_initial = False
            frames.append(SentAckFrame())
        push_ping_frame(payload_buf, PingFrame())
        frames.append(SentPingFrame())
        plain_payload = payload_buf.data
        pn = self._initial_pn
        header_buf = Buffer()
        ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
        push_initial_packet_header(
            header_buf,
            destination_cid=self._peer_cid,
            source_cid=self._our_cid,
            token=b"",
            payload_length=ciphertext_len,
        )
        plain_header = header_buf.data
        encrypted = self._initial_crypto.encrypt_packet(plain_header, plain_payload, pn)
        self._send_queue.append(encrypted)
        self._initial_space.on_packet_sent(
            packet_number=pn,
            sent_time=now,
            sent_bytes=len(encrypted),
            ack_eliciting=True,
            in_flight=True,
            frames=tuple(frames),
        )
        self._initial_pn += 1

    def _queue_handshake_response(self, tls_data: bytes) -> None:
        """Queue Handshake packet(s) with TLS data in CRYPTO frames."""
        if not self._handshake_crypto or not self._our_cid or not self._peer_cid:
            return
        offset = 0
        while offset < len(tls_data):
            chunk = tls_data[offset : offset + MTU - 100]
            if not chunk:
                break
            payload_buf = Buffer()
            push_crypto_frame(payload_buf, CryptoFrame(offset=offset, data=chunk))
            plain_payload = payload_buf.data
            pn = self._handshake_pn
            pn_bytes = pn.to_bytes(PN_SIZE, "big")
            plain = pn_bytes + plain_payload
            ciphertext_len = len(plain) + AEAD_TAG_SIZE
            header_buf = Buffer()
            push_handshake_packet_header(
                header_buf,
                destination_cid=self._peer_cid,
                source_cid=self._our_cid,
                payload_length=ciphertext_len,
            )
            plain_header = header_buf.data
            encrypted = self._handshake_crypto.encrypt_packet(plain_header, plain_payload, pn)
            self._send_queue.append(encrypted)
            self._handshake_space.on_packet_sent(
                packet_number=pn,
                sent_time=self._now,
                sent_bytes=len(encrypted),
                ack_eliciting=True,
                in_flight=True,
                frames=(SentCryptoFrame(offset=offset, length=len(chunk)),),
            )
            self._handshake_pn += 1
            offset += len(chunk)

    def _build_ack_packet(
        self, ack_ranges: RangeSet, crypto: CryptoPair, pn: int, space: PacketSpace
    ) -> bytes:
        """Build a packet containing an ACK frame."""
        payload_buf = Buffer()
        ack = AckFrame(ranges=tuple(ack_ranges._ranges), delay=0)
        buf_type = Buffer()
        buf_type.push_uint_var(0x02)
        payload_buf.push_bytes(buf_type.data)
        push_ack_frame(payload_buf, ack)
        plain_payload = payload_buf.data
        header_buf = Buffer()
        push_short_header(header_buf, self._peer_cid, pn)
        plain_header = header_buf.data
        encrypted = crypto.encrypt_packet(plain_header, plain_payload, pn)
        # ACK-only packets are NOT ack-eliciting and NOT in-flight (RFC 9002)
        space.on_packet_sent(
            packet_number=pn,
            sent_time=self._now,
            sent_bytes=len(encrypted),
            ack_eliciting=False,
            in_flight=False,
            frames=(SentAckFrame(),),
        )
        return encrypted

    def send_datagrams(self, *, now: float = 0.0) -> list[bytes]:
        """Return queued datagrams to send."""
        if now > 0.0:
            self._now = now
        out, self._send_queue = self._send_queue, []

        # Generate pending ACKs
        if (
            self._ack_needed_handshake
            and self._handshake_crypto
            and len(self._handshake_ack_ranges) > 0
        ):
            ack_packet = self._build_ack_packet(
                self._handshake_ack_ranges,
                self._handshake_crypto,
                self._handshake_pn,
                self._handshake_space,
            )
            out.append(ack_packet)
            self._handshake_pn += 1
            self._ack_needed_handshake = False

        if (
            self._ack_needed_application
            and self._one_rtt_crypto
            and len(self._application_ack_ranges) > 0
        ):
            ack_packet = self._build_ack_packet(
                self._application_ack_ranges,
                self._one_rtt_crypto,
                self._one_rtt_pn,
                self._application_space,
            )
            out.append(ack_packet)
            self._one_rtt_pn += 1
            self._ack_needed_application = False

        # Re-queue HANDSHAKE_DONE if lost and needs retransmission
        if (
            self._handshake_done_pending
            and self._state == ConnectionState.ONE_RTT
            and self._one_rtt_crypto
            and self._peer_cid
        ):
            self._handshake_done_pending = False
            self._queue_handshake_done()
            # The queued packet was added to _send_queue, grab it
            out.extend(self._send_queue)
            self._send_queue = []

        # PTO probe: send PING to elicit ACK
        if (
            self._probe_needed
            and self._state == ConnectionState.ONE_RTT
            and self._one_rtt_crypto
            and self._peer_cid
        ):
            self._probe_needed = False
            payload_buf = Buffer()
            push_ping_frame(payload_buf, PingFrame())
            out.append(self._encrypt_short_packet(payload_buf.data, (SentPingFrame(),)))

        # Flush 0-RTT stream data (client only, before handshake completes)
        if self._zero_rtt_crypto and self._zero_rtt_stream_queue and self._peer_cid:
            out.extend(self._flush_zero_rtt_queue())

        if self._state == ConnectionState.ONE_RTT and self._stream_send_queue:
            out.extend(self._flush_stream_send_queue())

        # Anti-amplification (RFC 9000 §8): limit bytes sent before address validation
        if not self._address_validated:
            amplification_limit = 3 * self._bytes_received
            filtered: list[bytes] = []
            for dgram in out:
                if self._bytes_sent + len(dgram) <= amplification_limit:
                    self._bytes_sent += len(dgram)
                    filtered.append(dgram)
                else:
                    break
            out = filtered
        else:
            for dgram in out:
                self._bytes_sent += len(dgram)

        return out

    def _flush_zero_rtt_queue(self) -> list[bytes]:
        """Build 0-RTT long-header packets from queued early data."""
        if not self._zero_rtt_crypto or not self._peer_cid or not self._our_cid:
            return []
        packets: list[bytes] = []
        for stream_id, data, end_stream in self._zero_rtt_stream_queue:
            stream = self._get_or_create_stream(StreamId(stream_id))
            offset = stream._send.sent_end
            stream._send.write(data)
            payload_buf = Buffer()
            push_stream_frame(
                payload_buf,
                StreamFrame(
                    stream_id=StreamId(stream_id),
                    offset=offset,
                    data=data,
                    fin=end_stream,
                ),
            )
            stream._send.advance(len(data), fin=end_stream)
            plain_payload = payload_buf.data
            pn = self._one_rtt_pn  # 0-RTT shares Application PN space
            ciphertext_len = PN_SIZE + len(plain_payload) + AEAD_TAG_SIZE
            header_buf = Buffer()
            push_zero_rtt_packet_header(
                header_buf,
                destination_cid=self._peer_cid,
                source_cid=self._our_cid,
                payload_length=ciphertext_len,
            )
            plain_header = header_buf.data
            encrypted = self._zero_rtt_crypto.encrypt_packet(plain_header, plain_payload, pn)
            packets.append(encrypted)
            self._application_space.on_packet_sent(
                packet_number=pn,
                sent_time=self._now,
                sent_bytes=len(encrypted),
                ack_eliciting=True,
                in_flight=True,
                frames=(
                    SentStreamFrame(
                        stream_id=stream_id,
                        offset=offset,
                        length=len(data),
                        fin=end_stream,
                    ),
                ),
            )
            self._one_rtt_pn += 1
        self._zero_rtt_stream_queue = []
        return packets

    def _flush_stream_send_queue(self) -> list[bytes]:
        """Build Short header packets from _stream_send_queue, coalescing to MTU."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return []
        packets: list[bytes] = []
        # Coalesce multiple small STREAM frames into single packets
        payload_buf = Buffer()
        current_frames: list[SentStreamFrame] = []
        max_payload = MTU - 30 - AEAD_TAG_SIZE  # header + PN + AEAD overhead
        deferred: list[tuple[int, bytes, bool]] = []

        for stream_id, data, end_stream in self._stream_send_queue:
            # Congestion window gate: check if we can send more
            if not self._cc.can_send(MTU):
                deferred.append((stream_id, data, end_stream))
                continue
            stream = self._get_or_create_stream(StreamId(stream_id))
            offset = stream._send.sent_end

            # Buffer data for potential retransmission
            stream._send.write(data)

            frame_buf = Buffer()
            push_stream_frame(
                frame_buf,
                StreamFrame(
                    stream_id=StreamId(stream_id),
                    offset=offset,
                    data=data,
                    fin=end_stream,
                ),
            )
            frame_bytes = frame_buf.data
            stream._send.advance(len(data), fin=end_stream)

            sent_frame = SentStreamFrame(
                stream_id=stream_id, offset=offset, length=len(data), fin=end_stream
            )

            # If this frame doesn't fit in current packet, flush current
            if len(payload_buf.data) > 0 and len(payload_buf.data) + len(frame_bytes) > max_payload:
                packets.append(self._encrypt_short_packet(payload_buf.data, tuple(current_frames)))
                payload_buf = Buffer()
                current_frames = []

            payload_buf.push_bytes(frame_bytes)
            current_frames.append(sent_frame)

        # Flush remaining
        if len(payload_buf.data) > 0:
            packets.append(self._encrypt_short_packet(payload_buf.data, tuple(current_frames)))

        self._stream_send_queue = deferred
        return packets

    def _optimal_pn_length(self) -> int:
        """Compute optimal packet number encoding length (RFC 9000 17.1).

        Always returns 4 for now — the decrypt side hardcodes 4-byte PN
        parsing. Variable-length PN requires a two-pass header protection
        removal (RFC 9001 5.4.2) which isn't implemented yet.
        """
        return 4

    def _encrypt_short_packet(
        self,
        plain_payload: bytes,
        frames: tuple[
            SentStreamFrame | SentHandshakeDoneFrame | SentNewConnectionIdFrame | SentPingFrame,
            ...,
        ] = (),
    ) -> bytes:
        """Encrypt a short header packet with the given payload."""
        if not self._one_rtt_crypto:
            raise RuntimeError("1-RTT crypto not initialized")
        pn = self._one_rtt_pn
        pn_len = self._optimal_pn_length()
        header_buf = Buffer()
        push_short_header(header_buf, self._peer_cid, pn, pn_len=pn_len)
        plain_header = header_buf.data
        encrypted = self._one_rtt_crypto.encrypt_packet(plain_header, plain_payload, pn)
        ack_eliciting = any(not isinstance(f, SentAckFrame) for f in frames) if frames else True
        in_flight = ack_eliciting  # ACK-only packets are not in-flight
        self._application_space.on_packet_sent(
            packet_number=pn,
            sent_time=self._now,
            sent_bytes=len(encrypted),
            ack_eliciting=ack_eliciting,
            in_flight=in_flight,
            frames=frames,
        )
        if in_flight:
            self._cc.on_packet_sent(len(encrypted))
        self._one_rtt_pn += 1
        return encrypted

    # --- Session ticket methods ---

    def generate_session_ticket(self) -> tuple[bytes, SessionTicket]:
        """Server: generate a NewSessionTicket. Returns (nst_wire_bytes, SessionTicket).

        The nst_wire_bytes should be sent to the client (e.g. via a post-handshake message).
        The SessionTicket should be stored server-side for future PSK validation.
        """
        if not self._tls_ctx:
            raise RuntimeError("No TLS context — handshake not started")
        return self._tls_ctx.generate_session_ticket()

    def receive_new_session_ticket(self, data: bytes) -> SessionTicket:
        """Client: parse a NewSessionTicket message. Returns a SessionTicket."""
        if not self._client_tls_ctx:
            raise RuntimeError("No client TLS context")
        return self._client_tls_ctx.receive_new_session_ticket(data)

    # --- Public lifecycle methods ---

    def close(self, error_code: int = 0, reason: str = "") -> None:
        """Initiate graceful connection close. Queues CONNECTION_CLOSE frame."""
        if self._state == ConnectionState.CLOSED:
            return
        reason_bytes = reason.encode("utf-8") if reason else b""
        frame = ConnectionCloseFrame(error_code=error_code, reason_phrase=reason_bytes)
        payload_buf = Buffer()
        push_connection_close(payload_buf, frame)
        plain_payload = payload_buf.data

        if self._one_rtt_crypto and self._peer_cid:
            self._send_queue.append(self._encrypt_short_packet(plain_payload))
        elif self._handshake_crypto and self._our_cid and self._peer_cid:
            pn = self._handshake_pn
            pn_bytes = pn.to_bytes(PN_SIZE, "big")
            plain = pn_bytes + plain_payload
            ciphertext_len = len(plain) + AEAD_TAG_SIZE
            header_buf = Buffer()
            push_handshake_packet_header(
                header_buf,
                destination_cid=self._peer_cid,
                source_cid=self._our_cid,
                payload_length=ciphertext_len,
            )
            plain_header = header_buf.data
            encrypted = self._handshake_crypto.encrypt_packet(plain_header, plain_payload, pn)
            self._send_queue.append(encrypted)
            self._handshake_pn += 1

        self._state = ConnectionState.CLOSED

    def get_timer(self) -> float | None:
        """Return absolute time of next timer deadline, or None if no timer pending.

        Sans-I/O: the caller uses this to schedule when to call handle_timer().
        Returns the earliest of: idle timeout, PTO deadline.
        """
        if self._state == ConnectionState.CLOSED:
            return None
        deadlines: list[float] = []
        # Idle timeout
        if self._last_activity > 0.0 and self._config.idle_timeout > 0:
            deadlines.append(self._last_activity + self._config.idle_timeout)
        # PTO: if there are ack-eliciting packets in flight
        for space in (self._initial_space, self._handshake_space, self._application_space):
            if space.has_ack_eliciting_in_flight:
                # Find most recent sent time among in-flight packets
                latest_sent = max(
                    p.sent_time for p in space.sent_packets.values() if p.ack_eliciting
                )
                pto = self._rtt.pto_duration() * (2**self._pto_count)
                deadlines.append(latest_sent + pto)
        return min(deadlines) if deadlines else None

    def handle_timer(self, now: float) -> list[QuicEvent]:
        """Handle timer expiry. Called by the caller when get_timer() deadline passes.

        Sans-I/O: the library never sleeps. The caller provides the current time.
        """
        events: list[QuicEvent] = []
        if self._state == ConnectionState.CLOSED:
            return events
        self._now = now

        # Check idle timeout first
        if self._last_activity > 0.0 and self._config.idle_timeout > 0:
            idle_deadline = self._last_activity + self._config.idle_timeout
            if now >= idle_deadline:
                self._close_with_error(0, "idle timeout", events)
                return events

        # PTO expiry — send a probe (PING) and increment backoff
        for space in (self._initial_space, self._handshake_space, self._application_space):
            if space.has_ack_eliciting_in_flight:
                latest_sent = max(
                    p.sent_time for p in space.sent_packets.values() if p.ack_eliciting
                )
                pto = self._rtt.pto_duration() * (2**self._pto_count)
                if now >= latest_sent + pto:
                    self._pto_count += 1
                    self._probe_needed = True
                    break

        return events

    def _close_with_error(self, error_code: int, reason: str, events: list[QuicEvent]) -> None:
        """Close connection with error, queue CONNECTION_CLOSE, emit event."""
        if self._state == ConnectionState.CLOSED:
            return
        self.close(error_code=error_code, reason=reason)
        events.append(ConnectionClosed(error_code=error_code, reason=reason))
