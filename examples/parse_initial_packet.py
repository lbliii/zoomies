"""
Parse QUIC Initial packet header — sans-I/O packet inspection.

Demonstrates Zoomies' packet parsing: read a QUIC Initial packet's
long header (version, CIDs, token, payload length) without decrypting
the payload.

Run:
    python -m examples.parse_initial_packet

"""

from zoomies.encoding import Buffer
from zoomies.packet.header import LongHeader, pull_quic_header

# Minimal Initial packet (header only, from Zoomies test fixtures)
# Version 1, 8-byte dest CID, 8-byte src CID, empty token
PACKET = (
    bytes.fromhex("c300000001088394c8f03e51570808f067a5502a4262b500003200") + b"\x00" * 50
)  # payload placeholder

buf = Buffer(data=PACKET)
header = pull_quic_header(buf, host_cid_length=None)

assert isinstance(header, LongHeader)
print("QUIC Initial packet header:")
print(f"  Version: 0x{header.version:08x}")
print(f"  Packet type: {header.packet_type} (Initial)")
print(f"  Destination CID: {header.destination_cid.hex()}")
print(f"  Source CID: {header.source_cid.hex()}")
print(f"  Token length: {len(header.token)}")
print(f"  Payload length: {header.payload_length}")
print(f"\nHeader consumed {buf.tell()} bytes; {len(PACKET) - buf.tell()} bytes payload")
