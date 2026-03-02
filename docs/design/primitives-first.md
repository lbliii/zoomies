# Primitives-First Design: S-Tier QUIC/HTTP3

What makes Zoomies exceptional: build from protocol primitives up, with explicit contracts and canonical keys. No aioquic mimicry — a spec-driven, type-first architecture.

---

## S-Tier Differentiators

| Dimension | A-Tier (aioquic-style) | S-Tier (Zoomies) |
|-----------|------------------------|------------------|
| **Foundation** | Buffer + packet parsing | Primitives → encoding → frames → packets → crypto → connection |
| **Types** | Dataclasses where convenient | Every protocol concept is a typed primitive before implementation |
| **Keys** | Ad-hoc (cid, stream_id) | Canonical contract keys; one function per lookup domain |
| **State** | Implicit in objects | Explicit state machines; transitions are typed |
| **Invariants** | Tested after the fact | Types + contracts enforce invariants; tests verify round-trip |
| **Composition** | Large modules | Small, pure functions; compose up |
| **Spec alignment** | Code-first | RFC concepts modeled first; code implements the model |

**S-tier in one line:** The RFC is the source of truth; our types and contracts are the executable specification.

---

## Build Order: Primitives Up

```
Layer 0: Protocol Primitives (types only)
         Varint, ConnectionId, StreamId, PacketNumber, FrameType, ...
Layer 1: Encoding (pure functions)
         pull_varint, push_varint, pull_bytes, push_bytes
Layer 2: Frames (dataclasses + encode/decode)
         StreamFrame, AckFrame, ... ; pull_frame, push_frame
Layer 3: Packet Structure (header + opaque payload)
         PacketHeader, LongHeader, ShortHeader; pull_header, push_header
Layer 4: Crypto (protocol + impl)
         PacketProtector protocol; QuicCrypto impl
Layer 5: Stream State (dataclass + invariants)
         StreamReceiveState, StreamSendState
Layer 6: Connection State Machine
         ConnectionState enum; transitions; ConnectionId as key
Layer 7: HTTP/3 (QPACK + H3 frames)
         H3Frame, QpackEncoder/Decoder
```

Each layer depends only on layers below. No layer knows about layers above.

---

## Layer 0: Protocol Primitives

**Dataclasses and enums that model RFC concepts.** No I/O, no logic — just the types.

```python
# zoomies/primitives/types.py

from dataclasses import dataclass
from enum import IntEnum

# --- Identifiers (RFC 9000) ---

@dataclass(frozen=True, slots=True)
class ConnectionId:
    """0–20 bytes. Canonical key for a connection."""
    value: bytes

@dataclass(frozen=True, slots=True)
class StreamId:
    """62-bit. Bit 0 = initiator, bit 1 = direction (RFC 9000 2.1)."""
    value: int

@dataclass(frozen=True, slots=True)
class PacketNumber:
    """62-bit. Monotonically increasing per packet number space."""
    value: int

# --- Frame types (RFC 9000 12–19) ---

class FrameType(IntEnum):
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    # ... STREAM, MAX_DATA, etc.

# --- Packet types ---

class PacketType(IntEnum):
    INITIAL = 0
    ZERO_RTT = 1
    HANDSHAKE = 2
    RETRY = 3
    ONE_RTT = 4  # short header
```

**Contract:** These types are immutable. No `Any`. Bounds (e.g. StreamId 0–2^62-1) can be enforced in constructors or via `NewType` + validation.

---

## Contract Keys

**One canonical function per lookup domain.** Like Bengal's `content_key`, `watcher_key` — never use raw values for cross-boundary lookups.

```python
# zoomies/contracts/keys.py

def connection_key(cid: ConnectionId) -> str:
    """Canonical key for connection lookups. Use everywhere."""
    return cid.value.hex()

def stream_key(cid: ConnectionId, sid: StreamId) -> str:
    """Canonical key for stream lookups within a connection."""
    return f"{connection_key(cid)}:{sid.value}"

def packet_space_key(cid: ConnectionId, space: PacketNumberSpace) -> str:
    """Key for packet number / crypto state per space (initial, handshake, 1rtt)."""
    return f"{connection_key(cid)}:{space.name}"
```

**Rule:** Caches, indexes, and maps use these. Never `str(cid)` or `f"{cid}:{sid}"` ad-hoc.

---

## Layer 1: Encoding

**Pure functions.** No state. Input buffer + optional params → output or parsed value.

```python
# zoomies/encoding/varint.py

def pull_varint(buf: Buffer) -> int: ...
def push_varint(buf: Buffer, value: int) -> None: ...

# zoomies/encoding/bytes.py
def pull_bytes(buf: Buffer, n: int) -> bytes: ...
def push_bytes(buf: Buffer, data: bytes) -> None: ...
```

**Tests:** Hypothesis round-trip. `pull_varint(push_varint(x)) == x` for all valid x.

---

## Layer 2: Frames

**Each frame type is a frozen dataclass.** Encode/decode are pure.

```python
# zoomies/frames/stream.py

@dataclass(frozen=True, slots=True)
class StreamFrame:
    stream_id: StreamId
    offset: int
    data: bytes
    fin: bool

def pull_stream_frame(buf: Buffer) -> StreamFrame: ...
def push_stream_frame(buf: Buffer, frame: StreamFrame) -> None: ...
```

**Contract:** `pull_X` consumes exactly the frame from `buf`. `push_X` produces bytes that `pull_X` would parse back.

---

## Layer 3: Packet Structure

**Header is parsed; payload is opaque until crypto.** Header types are dataclasses.

```python
@dataclass(frozen=True, slots=True)
class LongHeader:
    version: int | None  # None = version negotiation
    packet_type: PacketType
    dest_cid: ConnectionId
    src_cid: ConnectionId
    packet_number: PacketNumber
    payload_length: int  # for parsing bounds
```

**Separation:** `pull_header(buf)` returns header + length. Payload decryption is Layer 4.

---

## Layer 4: Crypto

**Protocol for packet protection.** Implementation uses `cryptography`.

```python
# zoomies/crypto/protocol.py

class PacketProtector(Protocol):
    def protect(self, plain_header: bytes, plain_payload: bytes, pn: PacketNumber) -> bytes: ...
    def unprotect(self, encrypted: bytes, header_len: int, expected_pn: PacketNumber) -> tuple[bytes, bytes, PacketNumber]: ...
```

**Contract:** `unprotect(protect(h, p, pn)) == (h, p, pn)`.

---

## Layer 5: Stream State

**Receive and send state as dataclasses.** Invariants explicit.

```python
@dataclass(frozen=True, slots=True)
class StreamReceiveState:
    """Invariant: data is contiguous from offset 0; fin implies complete."""
    stream_id: StreamId
    data: bytes
    fin: bool
    max_offset: int  # flow control
```

**Contract:** Stream state is immutable; transitions produce new state.

---

## Layer 6: Connection State Machine

**Explicit states and transitions.** ConnectionId is the key.

```python
class ConnectionState(StrEnum):
    INITIAL = "initial"       # waiting for client initial
    HANDSHAKE = "handshake"   # TLS in progress
    ONE_RTT = "one_rtt"      # connected
    DRAINING = "draining"
    CLOSED = "closed"

@dataclass
class Connection:
    """Key: connection_key(cid). All lookups use that."""
    cid: ConnectionId
    state: ConnectionState
    # ... streams, crypto, etc.
```

**Contract:** Transitions are explicit. No implicit state changes.

---

## Layer 7: HTTP/3

**H3 frames and QPACK.** Same pattern: dataclasses for frame types, pure encode/decode.

---

## Protocols (Behavioral Contracts)

**Use `typing.Protocol` for "something that can X":**

```python
class BufferLike(Protocol):
    def pull_uint8(self) -> int: ...
    def push_uint8(self, value: int) -> None: ...
    def tell(self) -> int: ...
    def data_slice(self, start: int, end: int) -> bytes: ...

class FrameDecoder(Protocol):
    def decode(self, buf: BufferLike) -> Frame: ...

class FrameEncoder(Protocol):
    def encode(self, buf: BufferLike, frame: Frame) -> None: ...
```

**Benefit:** Implementations can vary (e.g. C-backed buffer later) without changing callers.

---

## What We Don't Copy from aioquic

- **Monolithic connection.py** — Split into state machine, stream manager, crypto manager; each has a clear contract.
- **Buffer as C extension** — Start with pure Python; optimize only if needed.
- **TLS as 76KB custom impl** — Use `cryptography`; our TLS layer is a thin adapter.
- **Test structure** — We test primitives first (Hypothesis), then integration. Not "test_packet.py" as a grab bag.
- **Events as an afterthought** — Events are part of the connection contract: `datagram_received(data) -> list[QuicEvent]`.

---

## Revised Implementation Order

1. **Primitives** — `ConnectionId`, `StreamId`, `PacketNumber`, `FrameType`, `PacketType`, etc.
2. **Contract keys** — `connection_key`, `stream_key`, `packet_space_key`.
3. **Encoding** — `varint`, `bytes`; Buffer protocol + impl.
4. **Frames** — One module per frame family; dataclasses + pull/push.
5. **Packet** — Header types; pull/push header (payload opaque).
6. **Crypto** — `PacketProtector` protocol; `QuicCrypto` impl.
7. **Stream** — State dataclasses; receive/send logic.
8. **Connection** — State machine; uses all above.
9. **HTTP/3** — QPACK + H3 frames.

Each step is shippable and testable before the next.

---

## Summary

**S-tier =**

- Primitives and contracts defined before implementation
- Canonical keys for all cross-boundary lookups
- Pure functions for encoding; state only where the protocol requires it
- Types that model the RFC; code that implements the model
- Composition from small, testable units

We don't follow aioquic's structure. We follow the RFC's structure, with types and contracts as the bridge.

---

## B-Stack References

Patterns from chirp, kida, and bengal that Zoomies can adopt.

### Chirp — Contracts and Frozen Dataclasses

**`chirp/contracts.py`** — Typed hypermedia contracts. Declarative metadata for routes and templates.

- **`FragmentContract`**, **`SSEContract`**, **`FormContract`**, **`RouteContract`** — Frozen dataclasses declaring what a route returns or expects. Used for compile-time validation.
- **`ContractIssue`** — Frozen dataclass for validation results (severity, category, message, template, route).
- **`check_hypermedia_surface(app)`** — Validates the full server–client boundary against contracts.

**Pattern:** Contracts are *declarations* attached to routes. A separate checker validates the surface. Same idea for Zoomies: `StreamContract`, `ConnectionContract` as metadata; validation runs at setup or in tests.

**`chirp/tests/test_contracts.py`** — Tests extractors, matchers, and full `check_hypermedia_surface` scenarios.

### Kida — Protocols for Mixins, Frozen AST Nodes

**`kida/compiler/_protocols.py`** — `CompilerCoreProtocol` defines the minimal contract for compiler mixins. Only host attributes and core methods; mixins declare their own methods via `TYPE_CHECKING`. Enables type-safe mixin composition without exposing implementation.

**`kida/nodes/functions.py`** — `Def`, `DefParam`, `Slot`, `SlotBlock`, `CallBlock` — all `@dataclass(frozen=True, slots=True)`. AST nodes are immutable; transformations produce new nodes.

**Pattern:** Protocols for behavioral contracts; frozen dataclasses for immutable data. Zoomies: `PacketProtector`, `BufferLike` protocols; `StreamFrame`, `ConnectionId` as frozen primitives.

### Bengal — Canonical Keys, Change Detection Contracts

**`bengal/build/contracts/keys.py`** — `CacheKey = NewType("CacheKey", str)`. Canonical key functions: `content_key`, `data_key`, `template_key`, `watcher_key`, `xref_path_key`. Rule: *all* cache lookups use these; never raw `str(path)`.

**`bengal/build/contracts/protocol.py`** — `ChangeDetector` protocol; `DetectionContext` frozen dataclass. Detectors receive context, return `ChangeDetectionResult`; no mutation of shared state.

**`bengal/build/contracts/results.py`** — `ChangeDetectionResult` frozen dataclass with `.merge()` for composition. `RebuildReason` with code + trigger. Immutable, thread-safe.

**Pattern:** One key function per lookup domain; protocols for composable pipelines; immutable results with merge. Zoomies: `connection_key`, `stream_key`; `QuicConnection` protocol; events as frozen dataclasses.

### Pounce — Sans-I/O Protocol Events

**`pounce/protocols/_base.py`** — `RequestReceived`, `BodyReceived`, `ConnectionClosed`, `Upgraded` — frozen dataclasses. `ProtocolHandler` protocol: `receive_data(data) -> list[ProtocolEvent]`, `send_response(...)`, `send_body(...)`. Sans-I/O: no socket, no asyncio; caller feeds bytes, reads events.

**Pattern:** Events as frozen dataclasses; handler as protocol. Zoomies: `DatagramReceived`, `StreamDataReceived`, `ConnectionClosed`; `QuicHandler` protocol with `datagram_received` / `send_datagrams`.
