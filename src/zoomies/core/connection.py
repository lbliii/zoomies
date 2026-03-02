"""QUIC server connection — sans-I/O state machine (RFC 9000)."""

import os
from enum import StrEnum

from cryptography.exceptions import InvalidTag

from zoomies.core.configuration import QuicConfiguration
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
from zoomies.frames.ack import pull_ack_frame
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

QUIC_VERSION_1 = 0x0000_0001
INITIAL_HEADER_LEN = 18
CRYPTO_FRAME_TYPE = 0x06


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
                pass
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

    @property
    def our_cid(self) -> bytes:
        """Our connection ID (server's CID). Set after first Initial packet."""
        return self._our_cid

    @property
    def our_cids(self) -> tuple[bytes, ...]:
        """All active connection IDs we've issued (for CID-based routing)."""
        return tuple(self._our_cids)

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
                ev = self._handle_initial(data, buf, header)
                events.extend(ev)
            elif header.packet_type == PACKET_TYPE_HANDSHAKE:
                ev = self._handle_handshake(data, buf, header)
                events.extend(ev)
            elif header.packet_type == PACKET_TYPE_ZERO_RTT:
                ev = self._handle_zero_rtt(data, buf, header)
                events.extend(ev)
        elif isinstance(header, ShortHeader):
            ev = self._handle_short(data, buf, header)
            events.extend(ev)

        return events

    def _handle_initial(self, data: bytes, buf: Buffer, header: LongHeader) -> list[QuicEvent]:
        """Handle Initial packet."""
        events: list[QuicEvent] = []
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
            return events

        try:
            _ph, plain_payload, _pn = self._initial_crypto.decrypt_packet(
                data, encrypted_offset, self._initial_pn
            )
            self._state = ConnectionState.HANDSHAKE
            self._queue_initial_response()
            events.extend(self._parse_payload_frames(plain_payload))
            self._feed_crypto_to_tls(events)
        except InvalidTag:
            self._queue_initial_response()
            self._state = ConnectionState.HANDSHAKE
        return events

    def _handle_handshake(self, data: bytes, buf: Buffer, header: LongHeader) -> list[QuicEvent]:
        """Handle Handshake packet."""
        events: list[QuicEvent] = []
        if not self._handshake_crypto:
            return events
        encrypted_offset = buf.tell()
        try:
            _ph, plain_payload, _pn = self._handshake_crypto.decrypt_packet(
                data, encrypted_offset, self._handshake_pn
            )
            events.extend(self._parse_payload_frames(plain_payload))
            self._feed_crypto_to_tls(events)
        except InvalidTag:
            pass
        return events

    def _handle_zero_rtt(self, data: bytes, buf: Buffer, header: LongHeader) -> list[QuicEvent]:
        """Handle 0-RTT packet. Stub: 0-RTT receive not yet implemented."""
        return []

    def _handle_short(self, data: bytes, buf: Buffer, header: ShortHeader) -> list[QuicEvent]:
        """Handle Short header (1-RTT)."""
        events: list[QuicEvent] = []
        if self._state != ConnectionState.ONE_RTT or not self._one_rtt_crypto:
            return events
        encrypted_offset = buf.tell()
        try:
            _ph, plain_payload, _pn = self._one_rtt_crypto.decrypt_packet(
                data, encrypted_offset, self._one_rtt_pn
            )
            events.extend(self._parse_payload_frames(plain_payload))
        except InvalidTag:
            pass
        return events

    def _feed_crypto_to_tls(self, events: list[QuicEvent]) -> None:
        """Feed contiguous CRYPTO data to TLS, queue Handshake packets."""
        if not self._tls_ctx:
            return
        merged = _merge_crypto_ranges(self._crypto_recv)
        to_feed = b""
        new_fed = self._crypto_fed
        for start, data in merged:
            if start <= new_fed:
                end = start + len(data)
                if end > new_fed:
                    to_feed += data[new_fed - start :]
                    new_fed = end
            else:
                break
        self._crypto_fed = new_fed
        if not to_feed:
            return
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

    def _parse_payload_frames(self, payload: bytes, *, is_0rtt: bool = False) -> list[QuicEvent]:
        """Parse QUIC frames from decrypted payload; collect CRYPTO for TLS."""
        result: list[QuicEvent] = []
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
                    self._crypto_recv.append((frame.offset, frame.data))
                elif first == 0x19:
                    frame = pull_retire_connection_id(buf)
                    cid = self._sequence_to_cid.pop(frame.sequence, None)
                    if cid is not None:
                        self._our_cids.discard(cid)
                        result.append(ConnectionIdRetired(connection_id=cid))
                elif (first & 0x08) == 0x08:
                    frame = pull_stream_frame(buf)
                    result.append(
                        StreamDataReceived(
                            stream_id=frame.stream_id.value,
                            data=frame.data,
                            end_stream=frame.fin,
                            is_0rtt=is_0rtt,
                        )
                    )
                else:
                    break
            except ValueError:
                break
        return result

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

    def _queue_initial_response(self) -> None:
        """Queue server Initial packet."""
        if not self._initial_crypto or not self._our_cid or not self._peer_cid:
            return
        payload_buf = Buffer()
        push_ping_frame(payload_buf, PingFrame())
        plain_payload = payload_buf.data
        pn = self._initial_pn
        header_buf = Buffer()
        ciphertext_len = 4 + len(plain_payload) + 16
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
        mtu = 1200
        while offset < len(tls_data):
            chunk = tls_data[offset : offset + mtu - 100]
            if not chunk:
                break
            payload_buf = Buffer()
            push_crypto_frame(payload_buf, CryptoFrame(offset=offset, data=chunk))
            plain_payload = payload_buf.data
            pn = self._handshake_pn
            pn_bytes = pn.to_bytes(4, "big")
            plain = pn_bytes + plain_payload
            ciphertext_len = len(plain) + 16
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

    def send_datagrams(self) -> list[bytes]:
        """Return queued datagrams to send."""
        out = self._send_queue[:]
        self._send_queue.clear()
        if self._state == ConnectionState.ONE_RTT and self._stream_send_queue:
            out.extend(self._flush_stream_send_queue())
        return out

    def _flush_stream_send_queue(self) -> list[bytes]:
        """Build Short header packets from _stream_send_queue."""
        if not self._one_rtt_crypto or not self._peer_cid:
            return []
        packets: list[bytes] = []
        for stream_id, data, end_stream in self._stream_send_queue:
            payload_buf = Buffer()
            push_stream_frame(
                payload_buf,
                StreamFrame(
                    stream_id=StreamId(stream_id),
                    offset=0,
                    data=data,
                    fin=end_stream,
                ),
            )
            plain_payload = payload_buf.data
            pn = self._one_rtt_pn
            header_buf = Buffer()
            push_short_header(header_buf, self._peer_cid, pn)
            plain_header = header_buf.data
            encrypted = self._one_rtt_crypto.encrypt_packet(plain_header, plain_payload, pn)
            packets.append(encrypted)
            self._one_rtt_pn += 1
        self._stream_send_queue.clear()
        return packets
