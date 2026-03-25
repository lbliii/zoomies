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
    DecryptionFailed,
    HandshakeComplete,
    QuicEvent,
    StopSendingReceived,
    StreamDataReceived,
    StreamReset,
)
from zoomies.frames.ack import AckFrame, RangeSet, pull_ack_frame, push_ack_frame
from zoomies.frames.common import (
    ConnectionCloseFrame,
    PingFrame,
    pull_padding_frame,
    pull_ping_frame,
    push_connection_close,
    push_ping_frame,
)
from zoomies.frames.connection_id import pull_retire_connection_id, push_new_connection_id
from zoomies.frames.crypto import CryptoFrame, pull_crypto_frame, push_crypto_frame
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
from zoomies.recovery import (
    CongestionController,
    PacketSpace,
    RttEstimator,
    SentAckFrame,
    SentCryptoFrame,
    SentHandshakeDoneFrame,
    SentNewConnectionIdFrame,
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
        self._address_validated = False
        # Retransmission queues for lost frames
        self._crypto_retransmit: list[tuple[int, bytes]] = []  # (offset, data)
        self._handshake_done_pending = False
        self._probe_needed = False

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

    def send_stream_data(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        """Queue stream data for sending (H3StreamSender protocol)."""
        self._stream_send_queue.append((stream_id, data, end_stream))

    def datagram_received(
        self, data: bytes, addr: tuple[str, int], *, now: float = 0.0
    ) -> list[QuicEvent]:
        """Process incoming datagram; returns events."""
        events: list[QuicEvent] = []
        events.append(DatagramReceived(data=data, addr=addr))
        self._peer_addr = addr
        self._now = now
        self._bytes_received += len(data)
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
            self._queue_initial_response(now=self._now)
            self._parse_payload_frames(plain_payload, events)
            self._feed_crypto_to_tls(events)
        except InvalidTag:
            events.append(DecryptionFailed(packet_type="initial"))

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
            events.append(DecryptionFailed(packet_type="handshake"))

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
            events.append(DecryptionFailed(packet_type="1rtt"))

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
            self._address_validated = True
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
                    if not stream._recv.flow_control_ok(frame.offset, len(frame.data)):
                        self._close_with_error(
                            0x03, "Flow control limit exceeded", events
                        )
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

    def _retransmit_lost(self, lost: list[object]) -> None:
        """Re-queue retransmittable frames from lost packets."""
        from zoomies.recovery.sent_packet import SentPacket as _SentPacket

        for pkt in lost:
            if not isinstance(pkt, _SentPacket):
                continue
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
                        self._stream_send_queue.append(
                            (frame.stream_id, data, frame.fin)
                        )
                elif isinstance(frame, SentHandshakeDoneFrame):
                    self._handshake_done_pending = True
                # SentAckFrame: NOT retransmitted (RFC 9002)
                # SentPingFrame: NOT retransmitted
                # SentNewConnectionIdFrame: NOT retransmitted (idempotent)

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
        self._application_space.on_packet_sent(
            packet_number=pn,
            sent_time=self._now,
            sent_bytes=len(encrypted),
            ack_eliciting=True,
            in_flight=True,
            frames=(SentNewConnectionIdFrame(sequence=sequence),),
        )
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
        self._application_space.on_packet_sent(
            packet_number=pn,
            sent_time=self._now,
            sent_bytes=len(encrypted),
            ack_eliciting=True,
            in_flight=True,
            frames=(SentHandshakeDoneFrame(),),
        )
        self._one_rtt_pn += 1

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
            out.append(
                self._encrypt_short_packet(payload_buf.data, (SentPingFrame(),))
            )

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
                packets.append(
                    self._encrypt_short_packet(payload_buf.data, tuple(current_frames))
                )
                payload_buf = Buffer()
                current_frames = []

            payload_buf.push_bytes(frame_bytes)
            current_frames.append(sent_frame)

        # Flush remaining
        if len(payload_buf.data) > 0:
            packets.append(
                self._encrypt_short_packet(payload_buf.data, tuple(current_frames))
            )

        self._stream_send_queue = deferred
        return packets

    def _optimal_pn_length(self) -> int:
        """Compute optimal packet number encoding length (RFC 9000 17.1).

        Uses the distance from the largest acknowledged PN to encode
        the minimum number of bytes needed.
        """
        largest_acked = self._application_space.largest_acked_packet
        if largest_acked is None:
            return 4  # no ACK yet, use full 4 bytes
        pn = self._one_rtt_pn
        distance = pn - largest_acked
        if distance < 0x80:
            return 1
        if distance < 0x8000:
            return 2
        return 4

    def _encrypt_short_packet(
        self,
        plain_payload: bytes,
        frames: tuple[
            SentStreamFrame
            | SentHandshakeDoneFrame
            | SentNewConnectionIdFrame
            | SentPingFrame,
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

    # --- Public lifecycle methods ---

    def close(self, error_code: int = 0, reason: str = "") -> None:
        """Initiate graceful connection close. Queues CONNECTION_CLOSE frame."""
        if self._state == ConnectionState.CLOSED:
            return
        reason_bytes = reason.encode("utf-8") if reason else b""
        frame = ConnectionCloseFrame(
            error_code=error_code, reason_phrase=reason_bytes
        )
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
            encrypted = self._handshake_crypto.encrypt_packet(
                plain_header, plain_payload, pn
            )
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

    def _close_with_error(
        self, error_code: int, reason: str, events: list[QuicEvent]
    ) -> None:
        """Close connection with error, queue CONNECTION_CLOSE, emit event."""
        if self._state == ConnectionState.CLOSED:
            return
        self.close(error_code=error_code, reason=reason)
        events.append(ConnectionClosed(error_code=error_code, reason=reason))
