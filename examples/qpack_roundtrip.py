"""
QPACK header encode/decode — HTTP/3 header compression.

Demonstrates Zoomies' QPACK implementation: encode headers to bytes,
decode back to headers. Uses static table for common headers, literal
encoding for custom ones.

Run:
    python -m examples.qpack_roundtrip

"""

from zoomies.h3 import Header, decode_headers, encode_headers

# Encode request-like headers
headers = [
    Header(name=":method", value="GET"),
    Header(name=":path", value="/api/users"),
    Header(name=":scheme", value="https"),
    Header(name="x-custom", value="my-value"),
]

encoded = encode_headers(headers)
decoded = decode_headers(encoded)

print("Original headers:")
for h in headers:
    print(f"  {h.name}: {h.value}")

print(f"\nEncoded: {len(encoded)} bytes")
print(f"Decoded: {len(decoded)} headers")
for h in decoded:
    print(f"  {h.name}: {h.value}")

assert [(h.name, h.value) for h in decoded] == [(h.name, h.value) for h in headers]
print("\n✓ Round-trip successful")
