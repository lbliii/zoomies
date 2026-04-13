# Epic: Sharp Edges v3 — Make Zoomies Powerful, Ergonomic, Intuitive, and Reliable

**Status**: Complete
**Created**: 2026-04-13
**Target**: v0.4.0
**Estimated Effort**: 20–30h
**Dependencies**: None (all changes internal; builds on sharp-edges v1 #20 and v2 #21)
**Source**: Fresh audit of v0.3.2 post-v2 codebase (15 findings across correctness, ergonomics, and guardrails)

---

## Why This Matters

Zoomies v0.3.2 has solid test coverage (461 tests) and a clean sans-I/O API, but a developer using the library as documented will hit crashes, silent misconfigurations, and broken features within the first hour of real-world use.

**Consequences:**
1. **Five `except` syntax bugs** crash the connection on any malformed datagram — every browser and real-world peer will trigger this (`except ValueError, BufferReadError:` is Python 2 syntax)
2. **`max_data` config field is never wired** to transport parameters — a user sets connection-level flow control, it silently does nothing, and peers get no flow control limit
3. **`now` parameter defaults to `0.0`** on both `datagram_received()` and `send_datagrams()` — timers, RTT estimation, loss detection, and idle timeout all silently break if the caller forgets to pass a timestamp
4. **`idle_timeout=30.0` does nothing** without an undocumented timer loop — the README never mentions `get_timer()`/`handle_timer()`, so users believe connections auto-close
5. **Examples use private internals** (`conn._state`, `conn._one_rtt_crypto`) that break on any refactor — users copying them build brittle code
6. **`settings_data()` crashes on second call** with no documentation of one-shot behavior
7. **`max_data=0` silently means unlimited** — a misbehaving peer can OOM the server with no warning

### Evidence Table

| # | Finding | Severity | Proposal Impact |
|---|---------|----------|-----------------|
| 1 | `except ValueError, BufferReadError:` in 5 locations — catches only ValueError | CRITICAL | FIXES (Sprint 1) |
| 2 | `max_data` config field never referenced in connection.py | HIGH | FIXES (Sprint 1) |
| 3 | `now: float = 0.0` default makes timers/RTT/loss silently inert | HIGH | FIXES (Sprint 1) |
| 4 | `idle_timeout` inoperative without undocumented timer loop | HIGH | FIXES (Sprint 3) |
| 5 | `NewSessionTicket` now emitted (fixed in v2) | — | ALREADY FIXED |
| 6 | `settings_data()` raises RuntimeError on second call | MEDIUM | FIXES (Sprint 2) |
| 7 | Dual public methods: `handle_event()` vs `stream_data_received()` | MEDIUM | FIXES (Sprint 2) |
| 8 | 0-RTT requires undocumented 6-step process | MEDIUM | FIXES (Sprint 3) |
| 9 | Examples use private internals (`conn._state`, etc.) | MEDIUM | FIXES (Sprint 3) |
| 10 | `verify_mode=True` default friction → users ship `verify_mode=False` | MEDIUM | FIXES (Sprint 2) |
| 11 | No validation on `idle_timeout` range (negative, zero) | LOW | FIXES (Sprint 2) |
| 12 | `max_data=0` means unlimited with no warning | LOW | FIXES (Sprint 2) |
| 13 | Transport params accept any varint without range validation | LOW | FIXES (Sprint 2) |
| 14 | Buffer error messages vague ("Read out of bounds") | LOW | FIXES (Sprint 2) |
| 15 | Old decryption keys retained indefinitely after key update | LOW | FIXES (Sprint 1) |

### Invariants

These must remain true throughout or we stop and reassess:

1. **All 461+ tests pass**: Every PR must pass `pytest tests/`. No regressions.
2. **Sans-I/O contract preserved**: No sprint introduces I/O, threading, or implicit timers. The caller still owns all I/O.
3. **Public API backward compatible**: Existing `QuicConnection` and `H3Connection` method signatures don't change. New parameters are keyword-only with backward-compatible defaults. Deprecations use `DeprecationWarning`, not removals.

---

## Target Architecture

After this epic, Zoomies should:
- **Never crash on malformed datagrams** — all exception handlers use correct Python 3 syntax
- **Honor all configuration fields** — `max_data` wired to transport parameters, `idle_timeout` documented with examples
- **Fail loudly on misuse** — `now=0.0` warns or raises, `max_data=0` warns, `idle_timeout<=0` raises
- **Have zero deprecated methods in public API** — `stream_data_received()` removed or hidden
- **Ship examples that only use public API** — no `conn._state` or other private access
- **Auto-discard old keys** — forward secrecy maintained without caller intervention
- **Document every caller contract** — timer loop, 0-RTT flow, cert setup all in README

---

## Sprint Structure

| Sprint | Focus | Effort | Risk | Ships Independently? |
|--------|-------|--------|------|---------------------|
| 1 | Correctness: except syntax, max_data wiring, now validation, key cleanup | 8h | Medium | Yes |
| 2 | Fail-fast validation: config guardrails, settings_data, API cleanup, buffer errors | 8h | Low | Yes |
| 3 | Ergonomics: timer docs, 0-RTT guide, example rewrite, README update | 6h | Low | Yes |

No Sprint 0 needed — design decisions were already made in v1 and v2 plans. All remaining work is implementation.

---

## Sprint 1: Correctness

**Goal**: Fix the bugs that crash connections or silently produce wrong behavior.

### Task 1.1 — Fix Python 2 `except` syntax (5 locations)

Change `except ValueError, BufferReadError:` to `except (ValueError, BufferReadError):` in all five locations. Similarly fix `except InvalidSignature, ValueError:`.

**Files**:
- `src/zoomies/packet/header.py:75`
- `src/zoomies/core/connection.py:927, 932`
- `src/zoomies/crypto/tls.py:418`
- `src/zoomies/crypto/tls.py:1114`

**Acceptance**:
- `rg 'except \w+, \w+:' src/` returns zero hits
- `pytest tests/` passes
- New test: malformed datagram with `BufferReadError` path is caught, emits `PacketDropped`, does not crash

### Task 1.2 — Wire `max_data` config to transport parameters

Populate `initial_max_data` in the QUIC transport parameters from `QuicConfiguration.max_data`. This enables connection-level flow control (currently only per-stream flow control works via `max_stream_data`).

**Files**:
- `src/zoomies/core/connection.py` — transport parameter construction (look for where `QuicTransportParameters` is built)
- `src/zoomies/core/connection.py` — enforce received `initial_max_data` when sending

**Acceptance**:
- `rg 'max_data' src/zoomies/core/connection.py` shows both config→transport-param and enforcement sites
- New test: connection with `max_data=1024` rejects peer that sends >1024 bytes total
- `pytest tests/` passes

### Task 1.3 — Validate `now` parameter on `datagram_received()` and `send_datagrams()`

Emit a `DeprecationWarning` when `now=0.0` is passed (default), with message: "Pass monotonic time to `now` for correct timer/RTT behavior. Default `now=0.0` will be removed in v1.0."

This preserves backward compatibility while making the problem visible. In v1.0, change the default to a required parameter.

**Files**:
- `src/zoomies/core/connection.py:359` (`datagram_received`)
- `src/zoomies/core/connection.py:1264` (`send_datagrams`)

**Acceptance**:
- Calling `datagram_received(data, addr)` without `now` emits `DeprecationWarning`
- Calling `send_datagrams()` without `now` emits `DeprecationWarning`
- Existing tests that pass `now=` continue to work silently
- `pytest tests/` passes (tests updated to pass `now=`)

### Task 1.4 — Auto-discard old decryption keys after PTO

After a key update, schedule old key discard based on PTO. Call `discard_old_keys()` from `handle_timer()` when the PTO deadline passes after the key update.

**Files**:
- `src/zoomies/core/connection.py` — track `_key_update_time` and check in `handle_timer()`
- `src/zoomies/crypto/quic_crypto.py:276` — `discard_old_keys()` already exists

**Acceptance**:
- New test: after key update, old keys are discarded after one PTO interval
- `rg 'discard_old_keys' src/zoomies/core/connection.py` shows the call site
- `pytest tests/` passes

---

## Sprint 2: Fail-Fast Validation & API Cleanup

**Goal**: Make misconfiguration and misuse produce clear errors instead of silent failures.

### Task 2.1 — Add `QuicConfiguration` guardrails

Validate in `__post_init__`:
- `idle_timeout < 0` → raise `ValueError("idle_timeout must be non-negative")`
- `idle_timeout == 0` → treat as "no idle timeout" (document this behavior)
- `max_data < 0` or `max_stream_data < 0` → raise `ValueError`
- `max_data == 0` → emit `warnings.warn("max_data=0 disables flow control — peer can send unlimited data")`
- `server_name == ""` → raise `ValueError("server_name must be None or a non-empty string")`

**Files**: `src/zoomies/core/configuration.py:89-96`
**Acceptance**:
- `QuicConfiguration(is_client=True, ca_certs=b"x", idle_timeout=-1)` raises `ValueError`
- `QuicConfiguration(is_client=True, ca_certs=b"x", max_data=0)` emits warning
- `pytest tests/` passes

### Task 2.2 — Validate transport parameter ranges

Add range checks for peer-sent transport parameters after parsing:
- `max_udp_payload_size` must be ≥ 1200
- `ack_delay_exponent` must be ≤ 20
- `active_connection_id_limit` must be ≥ 2

Invalid values → emit `PacketDropped(reason="invalid_transport_param:...")` and reject connection.

**Files**: `src/zoomies/packet/transport_params.py` (after line 92) or `src/zoomies/core/connection.py` (after parsing)
**Acceptance**:
- New test: peer sends `ack_delay_exponent=25` → connection rejected with `PacketDropped`
- `pytest tests/` passes

### Task 2.3 — Make `settings_data()` idempotent instead of crashing

Change `settings_data()` to return `None` on subsequent calls instead of raising `RuntimeError`. This is less surprising and matches the return type (`bytes | None`).

**Files**: `src/zoomies/h3/connection.py:186`
**Acceptance**:
- `h3.settings_data()` returns bytes on first call, `None` on second call (no exception)
- `pytest tests/` passes

### Task 2.4 — Remove deprecated `stream_data_received()` from public API

Mark `stream_data_received()` as private (`_stream_data_received`) or delete it entirely. It's been deprecated since v2 and `handle_event()` is the replacement.

**Files**: `src/zoomies/h3/connection.py`
**Acceptance**:
- `rg 'def stream_data_received' src/zoomies/h3/` returns zero public methods
- `pytest tests/` passes (tests updated to use `handle_event()`)

### Task 2.5 — Improve buffer error messages

Change `BufferReadError("Read out of bounds")` to include context:

```python
raise BufferReadError(
    f"Read out of bounds: requested {length} bytes at position {self._pos}, "
    f"but buffer has {len(self._data)} bytes total ({len(self._data) - self._pos} remaining)"
)
```

**Files**: `src/zoomies/encoding/buffer.py:63-64` and any other `BufferReadError` raise sites
**Acceptance**:
- Error message includes requested bytes, position, and buffer length
- `pytest tests/` passes

### Task 2.6 — Add `verify_mode=False` safety warning to README

The client example in the README currently shows `verify_mode=False` with no caveat. Add a comment: `# ⚠️ Test only — use ca_certs in production`.

**Files**: `README.md` (client example section)
**Acceptance**:
- `rg 'verify_mode=False' README.md` shows a safety comment on the same or adjacent line

---

## Sprint 3: Ergonomics & Documentation

**Goal**: Make the sans-I/O contracts discoverable and the examples copy-pasteable.

### Task 3.1 — Add timer loop to README

Add a "Timer Integration" section to the README showing the `get_timer()`/`handle_timer()` pattern. Reference `examples/realistic_server.py` for the full implementation.

**Files**: `README.md`
**Acceptance**:
- `rg 'get_timer' README.md` returns at least one match
- `rg 'handle_timer' README.md` returns at least one match
- Section explains the sans-I/O timer contract in ≤10 lines

### Task 3.2 — Document 0-RTT end-to-end flow in README

Add a "0-RTT Early Data" section summarizing the flow: capture `NewSessionTicket` → store ticket → reconnect with `session_ticket=` → check `ZeroRttAccepted`/`ZeroRttRejected`. Reference `examples/zero_rtt_resumption.py`.

**Files**: `README.md`
**Acceptance**:
- `rg '0-RTT' README.md` or `rg 'zero.*rtt' README.md -i` returns at least one match
- Section covers all 4 steps in ≤15 lines

### Task 3.3 — Rewrite `stream_echo.py` to use only public API

Remove all private attribute access (`conn._state`, `conn._our_cid`, `conn._one_rtt_crypto`, `conn._last_activity`). Either use the proper public setup path or restructure the example to avoid needing internal state.

**Files**: `examples/stream_echo.py`
**Acceptance**:
- `rg 'conn\._' examples/stream_echo.py` returns zero hits (no private access)
- Example still runs successfully
- `pytest tests/` passes

### Task 3.4 — Add API quick-reference to README

The README's API table is missing key methods. Add: `send_stream_data()`, `get_timer()`, `handle_timer()`, and the event types (`HandshakeComplete`, `StreamDataReceived`, `ConnectionClosed`, etc.).

**Files**: `README.md`
**Acceptance**:
- `rg 'send_stream_data' README.md` returns at least one match
- `rg 'HandshakeComplete' README.md` returns at least one match

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `now` deprecation warning breaks CI for downstream users | Medium | Medium | Warning only (not error); message tells users how to fix; removed in v1.0 not v0.4 |
| Removing `stream_data_received()` breaks existing code | Low | High | Library is pre-1.0 beta; emit `DeprecationWarning` for one release before removal if concerned (Task 2.4) |
| `max_data` wiring changes flow control behavior for existing users | Medium | Medium | Default is 1 MB (already set in v2); users who didn't set `max_data` get the same behavior; only `max_data=0` users are affected |
| Exception syntax fix changes error behavior | Low | Low | The fix makes the code do what it was always intended to do — catch both exceptions |
| Rewriting `stream_echo.py` may lose its pedagogical value | Low | Low | The public API should be sufficient; if not, that's a signal the public API is incomplete |

---

## Success Metrics

| Metric | Current (v0.3.2) | After Sprint 1 | After Sprint 3 |
|--------|------------------|-----------------|-----------------|
| Python 2 `except` syntax bugs | 5 | 0 | 0 |
| Config fields that silently do nothing | 1 (`max_data`) | 0 | 0 |
| API methods with `now=0.0` footgun | 2 | 0 (warned) | 0 (warned) |
| Undocumented caller contracts in README | 2 (timer, 0-RTT) | 2 | 0 |
| Examples using private internals | 1 (`stream_echo`) | 1 | 0 |
| Config fields without validation | 3 (`idle_timeout`, `max_data=0`, `server_name=""`) | 3 | 0 |
| Deprecated public methods | 1 (`stream_data_received`) | 1 | 0 |

---

## Relationship to Existing Work

- **Sharp-edges v1 (#20)** — Fixed 12 of 21 original findings (CRYPTO retransmit, key updates, Huffman, static table, dynamic table, address validation, config validation, send queue bounding, settings_data crash-on-dup, PacketNumberSpace dedup, broad except). **Prerequisite, complete.**
- **Sharp-edges v2 (#21)** — Fixed remaining 9 findings plus 3 new (NewSessionTicket emission, H3 encoder stream auto-allocation, PacketDropped diagnostic events, flow control defaults, realistic_server example). **Prerequisite, complete.**
- **This plan (v3)** — Addresses 15 findings discovered in a fresh audit of the post-v2 codebase. Focuses on correctness bugs that survived v1/v2, plus ergonomics and documentation gaps.

---

## Changelog

- 2026-04-13: Draft created from fresh audit of v0.3.2 post-v2 codebase (15 findings).
