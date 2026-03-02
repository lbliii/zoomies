"""QUIC transport parameters (RFC 9000 18)."""

from dataclasses import dataclass
from typing import Any

from zoomies.encoding import Buffer

# RFC 9000 18.2: Transport parameter IDs
TP_ORIGINAL_DESTINATION_CONNECTION_ID = 0x00
TP_MAX_IDLE_TIMEOUT = 0x01
TP_STATELESS_RESET_TOKEN = 0x02
TP_MAX_UDP_PAYLOAD_SIZE = 0x03
TP_INITIAL_MAX_DATA = 0x04
TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05
TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06
TP_INITIAL_MAX_STREAM_DATA_UNI = 0x07
TP_INITIAL_MAX_STREAMS_BIDI = 0x08
TP_INITIAL_MAX_STREAMS_UNI = 0x09
TP_ACK_DELAY_EXPONENT = 0x0A
TP_MAX_ACK_DELAY = 0x0B
TP_DISABLE_ACTIVE_MIGRATION = 0x0C
TP_INITIAL_SOURCE_CONNECTION_ID = 0x0F
TP_RETRY_SOURCE_CONNECTION_ID = 0x10


@dataclass(frozen=True, slots=True)
class QuicTransportParameters:
    """QUIC transport parameters (RFC 9000 18.2)."""

    original_destination_connection_id: bytes | None = None
    max_idle_timeout: int | None = None
    stateless_reset_token: bytes | None = None
    max_udp_payload_size: int | None = None
    initial_max_data: int | None = None
    initial_max_stream_data_bidi_local: int | None = None
    initial_max_stream_data_bidi_remote: int | None = None
    initial_max_stream_data_uni: int | None = None
    initial_max_streams_bidi: int | None = None
    initial_max_streams_uni: int | None = None
    ack_delay_exponent: int | None = None
    max_ack_delay: int | None = None
    disable_active_migration: bool = False
    initial_source_connection_id: bytes | None = None
    retry_source_connection_id: bytes | None = None


_PARAM_IDS: dict[int, tuple[str, str]] = {
    TP_ORIGINAL_DESTINATION_CONNECTION_ID: ("original_destination_connection_id", "bytes"),
    TP_MAX_IDLE_TIMEOUT: ("max_idle_timeout", "int"),
    TP_STATELESS_RESET_TOKEN: ("stateless_reset_token", "bytes"),
    TP_MAX_UDP_PAYLOAD_SIZE: ("max_udp_payload_size", "int"),
    TP_INITIAL_MAX_DATA: ("initial_max_data", "int"),
    TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: ("initial_max_stream_data_bidi_local", "int"),
    TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: ("initial_max_stream_data_bidi_remote", "int"),
    TP_INITIAL_MAX_STREAM_DATA_UNI: ("initial_max_stream_data_uni", "int"),
    TP_INITIAL_MAX_STREAMS_BIDI: ("initial_max_streams_bidi", "int"),
    TP_INITIAL_MAX_STREAMS_UNI: ("initial_max_streams_uni", "int"),
    TP_ACK_DELAY_EXPONENT: ("ack_delay_exponent", "int"),
    TP_MAX_ACK_DELAY: ("max_ack_delay", "int"),
    TP_DISABLE_ACTIVE_MIGRATION: ("disable_active_migration", "bool"),
    TP_INITIAL_SOURCE_CONNECTION_ID: ("initial_source_connection_id", "bytes"),
    TP_RETRY_SOURCE_CONNECTION_ID: ("retry_source_connection_id", "bytes"),
}


def pull_quic_transport_parameters(buf: Buffer) -> QuicTransportParameters:
    """Parse transport parameters from buffer."""
    params: dict[str, int | bytes | bool] = {}
    while not buf.eof():
        param_id = buf.pull_uint_var()
        param_len = buf.pull_uint_var()
        start = buf.tell()
        if param_id in _PARAM_IDS:
            name, ptype = _PARAM_IDS[param_id]
            if ptype == "int":
                params[name] = buf.pull_uint_var()
            elif ptype == "bytes":
                params[name] = buf.pull_bytes(param_len)
            else:
                params[name] = True
        else:
            buf.pull_bytes(param_len)
        if buf.tell() != start + param_len:
            raise ValueError("Transport parameter length mismatch")
    kwargs: dict[str, Any] = {}
    for name, ptype in _PARAM_IDS.values():
        val = params.get(name)
        if ptype == "bool":
            kwargs[name] = bool(val) if val is not None else False
        else:
            kwargs[name] = val
    return QuicTransportParameters(**kwargs)


def push_quic_transport_parameters(buf: Buffer, params: QuicTransportParameters) -> None:
    """Serialize transport parameters to buffer."""
    for param_id, (name, ptype) in _PARAM_IDS.items():
        value = getattr(params, name)
        if value is None or (ptype == "bool" and not value):
            continue
        param_buf = Buffer()
        if ptype == "int":
            param_buf.push_uint_var(value)
        elif ptype == "bytes":
            param_buf.push_bytes(value)
        buf.push_uint_var(param_id)
        buf.push_uint_var(len(param_buf.data))
        buf.push_bytes(param_buf.data)
