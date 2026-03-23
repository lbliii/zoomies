"""QUIC server connection — sans-I/O state machine (RFC 9000)."""

import bisect
import os
from enum import StrEnum

from cryptography.exceptions import InvalidTag

from zoomies.core.configuration import QuicConfiguration
from zoomies.core.stream import Stream
from zoomies.crypto import CryptoPair, QuicTlsContext
from zoomies.encoding import Buffer
from zoomies.events import (
    ConnectionClosed,
    ConnectionIdIssued,
    ConnectionIdRetired,
    DatagramReceived,
    HandshakeComplete,
    QuicEvent,
    StreamDataReceived,
)
from zoomies.frames.ack import AckFrame, RangeSet, pull_ack_frame, push_ack_frame
from zoomies.frames.common import (
    PingFrame,
    pull_padding_frame,
    pull_ping_frame,
    push_ping_frame,
)
from zoomies.frames.connection_id import pull_retire_connection_id, push_new_connection_id
from zoomies.frames.crypto import CryptoFrame, pull_crypto_frame, push_crypto_frame
from zoomies.frames.stream import (
    StreamFrame,
    pull_stream_frame,
    push_stream_frame,
)
from zoomies.packet.builder import (
    push_handshake_packet_header,
    push_initial_packet_header,
    push_short_header,
)
from zoomies.packet.header import (
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    LongHeader,
    ShortHeader,
    pull_quic_header,
)
from zoomies.primitives import StreamId

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
    """QUIC server connection — datagram_received, send_datagrams."""

    def __init__(self, config: QuicConfiguration) -> None:
        self._config = config
        self._state = ConnectionState.INITIAL
        self._initial_crypto: CryptoPair | None = None
        self._handshake_crypto: CryptoPair | None = None
        self._one_rtt_crypto: CryptoPair | None = None
        self._tls_ctx: QuicTlsContext | None = None
        self._our_cid = b""
        self._peer_cid = b""
        self._peer_addr: tuple[str, int] = ("", 0)
        self._send_queue: list[bytes] = []
        self._initial_pn = 0
        self._handshake_pn = 0
        self._one_rtt_pn = 0
        self._stream_send_queue: list[tuple[int, bytes, bool]] = []
        self._crypto_recv: list[tuple[int, bytes]] = []
        self._crypto_fed = 0
        self._our_cids: set[bytes] = set()
        self._sequence_to_cid: dict[int, bytes] = {}
        self._next_cid_sequence = 0
        # Stream state for reassembly and offset tracking
        self._streams: dict[int, Stream] = {}
        # ACK tracking — received packet numbers per space
        self._initial_ack_ranges = RangeSet()
        self._handshake_ack_ranges = RangeSet()
        self._application_ack_ranges = RangeSet()
        self._ack_needed_initial = False
        self._ack_needed_handshake = False
        self._ack_needed_application = False

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
            self._streams[sid] = Stream(stream_id)
        return self._streams[sid]

    def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
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
                pass  # 0-RTT not yet implemented
        elif isinstance(header, ShortHeader):
            self._handle_short(data, buf, header, events)

        return events

    def _handle_initial(
        self, data: bytes, buf: Buffer, header: LongHeader, events: list[QuicEvent]
    ) -> None:
        """Handle Initial packet."""
        encrypted_offset = buf.tell()

        if self._state == ConnectionState.INITIAL:
            self._our_cid = header.destination_cid
            self._our_cids = {self._our_cid}
            self._sequence_to_cid = {0: self._our_cid}
            self._next_cid_sequence = 1
            self._peer_cid = header.source_cid
            self._initial_crypto = CryptoPair()
            self._initial_crypto.setup_initial(cid=self._our_cid, is_client=False)
            self._tls_ctx = QuicTlsContext(
                certificate=self._config.certificate,
                private_key=self._config.private_key,
            )

        if not self._initial_crypto:
            return

        try:
            _ph, plain_payload, pn = self._initial_crypto.decrypt_packet(
                data, encrypted_offset, self._initial_pn
            )
            self._initial_ack_ranges.add(pn)
            self._ack_needed_initial = True
            self._state = ConnectionState.HANDSHAKE
            self._queue_initial_response()
            self._parse_payload_frames(plain_payload, events)
            self._feed_crypto_to_tls(events)
        except InvalidTag:
            self._queue_initial_response()
            self._state = ConnectionState.HANDSHAKE

    def _handle_handshake(
        self, data: bytes, buf: Buffer, header: LongHeader, events: list[QuicEvent]
    ) -> None:
        """Handle Handshake packet."""
        if not self._handshake_crypto:
            return
        encrypted_offset = buf.tell()
        try:
            _ph, plain_payload, pn = self._handshake_crypto.decrypt_packet(
                data, encrypted_offset, self._handshake_pn
            )
            self._handshake_ack_ranges.add(pn)
            self._ack_needed_handshake = True
            self._parse_payload_frames(plain_payload, events)
            self._feed_crypto_to_tls(events)
        except InvalidTag:
            pass

    def _handle_short(
        self, data: bytes, buf: Buffer, header: ShortHeader, events: list[QuicEvent]
    ) -> None:
        """Handle Short header (1-RTT)."""
        if self._state != ConnectionState.ONE_RTT or not self._one_rtt_crypto:
            return
        encrypted_offset = buf.tell()
        try:
            _ph, plain_payload, pn = self._one_rtt_crypto.decrypt_packet(
                data, encrypted_offset, self._one_rtt_pn
            )
            self._application_ack_ranges.add(pn)
            self._ack_needed_application = True
            self._parse_payload_frames(plain_payload, events)
        except InvalidTag:
            pass

    def _feed_crypto_to_tls(self, events: list[QuicEvent]) -> None:
        """Feed contiguous CRYPTO data to TLS, queue Handshake packets."""
        if not self._tls_ctx:
            return
        merged = _merge_crypto_ranges(self._crypto_recv)
        parts: list[bytes] = []
        new_fed = self._crypto_fed
        for start, data in merged:
            if start <= new_fed:
                end = start + len(data)
                if end > new_fed:
                    parts.append(data[new_fed - start :])
                    new_fed = end
            else:
                break
        self._crypto_fed = new_fed
        # Prune consumed ranges
        self._crypto_recv = [(s, d) for s, d in self._crypto_recv if s + len(d) > new_fed]
        if not parts:
            return
        to_feed = b"".join(parts)
        result = self._tls_ctx.receive(to_feed)
        if result.handshake_secret and not self._handshake_crypto:
            self._handshake_crypto = CryptoPair()
            self._handshake_crypto.setup_handshake(result.handshake_secret, is_client=False)
        if result.data_to_send:
            self._queue_handshake_response(result.data_to_send)
        if result.traffic_secret and not self._one_rtt_crypto:
            self._one_rtt_crypto = CryptoPair()
            self._one_rtt_crypto.setup_1rtt(result.traffic_secret, is_client=False)
            self._state = ConnectionState.ONE_RTT
            events.append(HandshakeComplete())
            self._queue_new_connection_id(events)
            self._queue_handshake_done()

    def _parse_payload_frames(
        self, payload: bytes, events: list[QuicEvent], *, is_0rtt: bool = False
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
                    pull_ack_frame(buf)
                elif first == CRYPTO_FRAME_TYPE:
                    frame = pull_crypto_frame(buf)
                    bisect.insort(self._crypto_recv, (frame.offset, frame.data))
                elif first == 0x19:
                    frame = pull_retire_connection_id(buf)
                    cid = self._sequence_to_cid.pop(frame.sequence, None)
                    if cid is not None:
                        self._our_cids.discard(cid)
                        events.append(ConnectionIdRetired(connection_id=cid))
                elif first == HANDSHAKE_DONE_FRAME_TYPE:
                    buf.pull_uint_var()  # consume frame type
                elif (first & 0x08) == 0x08:
                    frame = pull_stream_frame(buf)
                    stream = self._get_or_create_stream(frame.stream_id)
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

    def _queue_new_connection_id(self, events: list[QuicEvent]) -> None:
        """Queue 1-RTT packet with NEW_CONNECTION_ID for connection migration."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return
        new_cid = os.urandom(8)
        sequence = self._next_cid_sequence
        self._next_cid_sequence += 1
        self._sequence_to_cid[sequence] = new_cid
        self._our_cids.add(new_cid)
        events.append(ConnectionIdIssued(connection_id=new_cid, retire_prior_to=0))
        payload_buf = Buffer()
        push_new_connection_id(
            payload_buf,
            sequence=sequence,
            retire_prior_to=0,
            connection_id=new_cid,
        )
        plain_payload = payload_buf.data
        pn = self._one_rtt_pn
        header_buf = Buffer()
        push_short_header(header_buf, self._peer_cid, pn)
        plain_header = header_buf.data
        encrypted = self._one_rtt_crypto.encrypt_packet(plain_header, plain_payload, pn)
        self._send_queue.append(encrypted)
        self._one_rtt_pn += 1

    def _queue_handshake_done(self) -> None:
        """Queue HANDSHAKE_DONE frame in a 1-RTT packet (RFC 9000 19.20)."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return
        payload_buf = Buffer()
        payload_buf.push_uint_var(HANDSHAKE_DONE_FRAME_TYPE)
        plain_payload = payload_buf.data
        pn = self._one_rtt_pn
        header_buf = Buffer()
        push_short_header(header_buf, self._peer_cid, pn)
        plain_header = header_buf.data
        encrypted = self._one_rtt_crypto.encrypt_packet(plain_header, plain_payload, pn)
        self._send_queue.append(encrypted)
        self._one_rtt_pn += 1

    def _queue_initial_response(self) -> None:
        """Queue server Initial packet."""
        if not self._initial_crypto or not self._our_cid or not self._peer_cid:
            return
        payload_buf = Buffer()
        # Include ACK if we have received Initial packets
        if len(self._initial_ack_ranges) > 0:
            ack = AckFrame(ranges=tuple(self._initial_ack_ranges._ranges), delay=0)
            buf_type = Buffer()
            buf_type.push_uint_var(0x02)  # ACK frame type
            payload_buf.push_bytes(buf_type.data)
            push_ack_frame(payload_buf, ack)
            self._ack_needed_initial = False
        push_ping_frame(payload_buf, PingFrame())
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
            self._handshake_pn += 1
            offset += len(chunk)

    def _build_ack_packet(self, ack_ranges: RangeSet, crypto: CryptoPair, pn: int) -> bytes:
        """Build a 1-RTT packet containing an ACK frame."""
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
        return crypto.encrypt_packet(plain_header, plain_payload, pn)

    def send_datagrams(self) -> list[bytes]:
        """Return queued datagrams to send."""
        out, self._send_queue = self._send_queue, []

        # Generate pending ACKs
        if (
            self._ack_needed_handshake
            and self._handshake_crypto
            and len(self._handshake_ack_ranges) > 0
        ):
            ack_packet = self._build_ack_packet(
                self._handshake_ack_ranges, self._handshake_crypto, self._handshake_pn
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
                self._application_ack_ranges, self._one_rtt_crypto, self._one_rtt_pn
            )
            out.append(ack_packet)
            self._one_rtt_pn += 1
            self._ack_needed_application = False

        if self._state == ConnectionState.ONE_RTT and self._stream_send_queue:
            out.extend(self._flush_stream_send_queue())

        return out

    def _flush_stream_send_queue(self) -> list[bytes]:
        """Build Short header packets from _stream_send_queue, coalescing to MTU."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return []
        packets: list[bytes] = []
        # Coalesce multiple small STREAM frames into single packets
        payload_buf = Buffer()
        max_payload = MTU - 30 - AEAD_TAG_SIZE  # header + PN + AEAD overhead

        for stream_id, data, end_stream in self._stream_send_queue:
            stream = self._get_or_create_stream(StreamId(stream_id))
            offset = stream._send.sent_end

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

            # If this frame doesn't fit in current packet, flush current
            if len(payload_buf.data) > 0 and len(payload_buf.data) + len(frame_bytes) > max_payload:
                packets.append(self._encrypt_short_packet(payload_buf.data))
                payload_buf = Buffer()

            payload_buf.push_bytes(frame_bytes)

        # Flush remaining
        if len(payload_buf.data) > 0:
            packets.append(self._encrypt_short_packet(payload_buf.data))

        self._stream_send_queue.clear()
        return packets

    def _encrypt_short_packet(self, plain_payload: bytes) -> bytes:
        """Encrypt a short header packet with the given payload."""
        if not self._one_rtt_crypto:
            raise RuntimeError("1-RTT crypto not initialized")
        pn = self._one_rtt_pn
        header_buf = Buffer()
        push_short_header(header_buf, self._peer_cid, pn)
        plain_header = header_buf.data
        encrypted = self._one_rtt_crypto.encrypt_packet(plain_header, plain_payload, pn)
        self._one_rtt_pn += 1
        return encrypted
