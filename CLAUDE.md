# CLAUDE.md — Using Zoomies from an AI Agent

This guide is for AI coding agents (or any developer moving fast) consuming
zoomies as a dependency. For contributor conventions see [AGENTS.md](AGENTS.md).
For install + longer-form quickstart see [README.md](README.md).

---

## 1. 60-Second Orientation

Zoomies is a **sans-I/O** QUIC + HTTP/3 implementation in pure Python 3.14+.

- **It is**: a protocol engine you wrap with your own transport. Deterministic,
  testable, transport-agnostic.
- **It is not**: an async framework, an HTTP client, or a drop-in replacement
  for `aiohttp` / `httpx` / `requests`.

Reach for zoomies when you need:
- custom transport (kernel-bypass, in-memory, testing harness)
- protocol-level control (custom CID routing, per-stream policies)
- deterministic test doubles of a QUIC peer

Don't reach for zoomies when you just want to `GET` a URL. Use `httpx` instead.

## 2. The Mental Model

The entire public API reduces to three flows:

```
datagrams in  →  conn.datagram_received(data, addr, now=T)  →  list[QuicEvent]
app action    →  conn.send_stream_data(sid, payload)
                 conn.send_datagrams(now=T)                 →  list[bytes] to sock
time passes   →  conn.get_timer() + conn.handle_timer(now=T) →  list[QuicEvent]
```

You own the socket. You own the clock. You own the event loop. Zoomies owns
the state machine.

Events are frozen dataclasses (see `zoomies.events`). The complete union type
is `QuicEvent`; pattern-match on it.

## 3. The Canonical Client Loop

Runnable as-is. Substitute cert/hostname to point at a real server.

```python
import select, socket, time
from zoomies import QuicConfiguration, QuicConnection, HandshakeComplete, StreamDataReceived

SERVER = ("127.0.0.1", 4433)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setblocking(False)

conn = QuicConnection(QuicConfiguration(
    is_client=True,
    verify_mode=False,       # skip cert validation for loopback; set ca_certs for prod
    server_name="localhost",
    idle_timeout=30.0,
))
conn.connect()                # generates Initial packet with ClientHello

while True:
    now = time.monotonic()
    deadline = conn.get_timer()
    timeout = max(0.0, deadline - now) if deadline is not None else 1.0
    readable, _, _ = select.select([sock], [], [], timeout)
    now = time.monotonic()
    if readable:
        data, addr = sock.recvfrom(65535)
        for event in conn.datagram_received(data, addr, now=now):
            if isinstance(event, HandshakeComplete):
                conn.send_stream_data(0, b"hello", end_stream=True)
            elif isinstance(event, StreamDataReceived):
                print("got:", event.data)
    else:
        conn.handle_timer(now=now)
    for dg in conn.send_datagrams(now=now):
        sock.sendto(dg, SERVER)
```

For a working server version see `examples/realistic_server.py`.

## 4. Timing Contract

The sans-I/O library never sleeps. You must drive the clock. Ignore this and
idle timeout, loss recovery, and ACK timers **silently** do nothing.

- `now` is **`time.monotonic()`**, not `time.time()`. Wall-clock jumps
  (NTP, DST, suspend) look like loss events to the recovery algorithm.
- `now` **must be non-decreasing** across calls. The loss detector assumes
  time moves forward.
- `get_timer()` returns an **absolute monotonic deadline** (or `None`).
- `handle_timer(now)` fires all timers due by `now`. Call it when the deadline
  passes **or** on every wake-up — idempotent.
- Call `send_datagrams(now=now)` after *every* `datagram_received` and *every*
  `handle_timer` to flush generated packets.

If `now<=0.0` is passed to `send_datagrams`, zoomies emits a `DeprecationWarning`
and skips loss detection for that call. Always pass `time.monotonic()`.

## 5. Event Cheatsheet

Every event your handler may receive. Pattern-match on the union type.

| Event | When | Action |
|---|---|---|
| `HandshakeComplete` | 1-RTT keys installed | Start sending stream data |
| `StreamDataReceived` | App bytes arrived | Process; check `end_stream`; check `is_0rtt` |
| `StreamReset` | Peer aborted a stream | Stop buffering; trust `final_size` |
| `StopSendingReceived` | Peer wants us to stop sending | Stop queuing to that stream |
| `ConnectionClosed` | Peer/self closed | Drain remaining datagrams, then exit |
| `ConnectionMigrated` | Peer moved addresses | Update your address book |
| `ConnectionIdIssued` | Peer gave us a new CID | If custom-routing: add to table |
| `ConnectionIdRetired` | Peer retired one of our CIDs | Remove from routing table |
| `DecryptionFailed` | Bad peer packet | Informational — **do not** respond (amplification) |
| `PacketDropped` | Diagnostic: datagram ignored | Logs only |
| `RetryReceived` | Server asked for stateless retry | Library handles token resend |
| `ZeroRttAccepted` | Server accepted 0-RTT early data | Queued streams are live |
| `ZeroRttRejected` | Server rejected 0-RTT | **Resend the queued streams as 1-RTT** |
| `NewSessionTicket` | Server issued TLS ticket (client) | Store ticket for reconnect + 0-RTT |
| `DatagramReceived` | Raw peer datagram | Low-level; usually ignore |
| `H3HeadersReceived` | HTTP/3 headers parsed | Read `headers: list[tuple[bytes, bytes]]` |
| `H3DataReceived` | HTTP/3 body chunk | Read `data`; check `end_stream` |

## 6. Top-5 Foot-Guns

### 6.1 "My client hangs forever."

**Cause**: you aren't calling `get_timer()` / `handle_timer()`.
**Fix**: copy the timer block from §3. No timers → no idle close, no loss retransmit.

### 6.2 "Loss recovery doesn't fire under packet loss."

**Cause**: same as 6.1, or you're passing `time.time()` as `now`.
**Fix**: always `now=time.monotonic()`. Loss detector assumes monotonic, non-decreasing time.

### 6.3 "Server 'accepted' 0-RTT but the action didn't happen."

**Cause**: you treated `StreamDataReceived(is_0rtt=True)` as committed.
**Fix**: 0-RTT data is **replayable** (RFC 9001 §9.2). Do not run non-idempotent
operations until you see `HandshakeComplete`. On the client side, if you get
`ZeroRttRejected`, resend queued streams.

### 6.4 "`send_stream_data()` raises `BufferError`."

**Cause**: send queue hit `max_send_queue_bytes` (default 16 MB).
**Fix**: drain with `send_datagrams()` more often, or raise the cap in
`QuicConfiguration(max_send_queue_bytes=...)`.

### 6.5 "Client silently skips cert validation."

**Cause**: `QuicConfiguration(is_client=True, verify_mode=False)` — convenient
for loopback, dangerous in prod.
**Fix**: for production clients pass `ca_certs=<PEM bytes>` and leave
`verify_mode=True`. The config will raise if you enable `verify_mode` without
providing `ca_certs`.

## 7. Where to Go Next

- Quickstart + install: [README.md](README.md)
- Contributor conventions (sharp edges, RFC discipline): [AGENTS.md](AGENTS.md)
- Runnable demos: [`examples/`](examples/) — `client_server.py`, `realistic_server.py`, `zero_rtt_resumption.py`
- Protocol specs: RFC 9000 (QUIC transport), RFC 9001 (QUIC+TLS), RFC 9114 (HTTP/3), RFC 9204 (QPACK)
