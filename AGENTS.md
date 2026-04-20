# AGENTS.md

Zoomies is a protocol library. It does not own sockets, it does not see users, it does not log to your dashboard — it just decides what bytes mean. When you change something here, wire-level consequences ride on it: the server using Zoomies can't fix your bug at a higher layer. Treat the rules below as safety rules, not style rules.

---

## North star

**Make QUIC and HTTP/3 worth running on free-threaded Python.** Zoomies exists to give 3.14t a pure-Python, sans-I/O QUIC stack that Pounce (and anyone else) can trust. Every decision routes back to that: RFC fidelity, types as contracts, correctness under true parallelism, zero native code. If a change doesn't serve that goal, it isn't worth shipping.

---

## Design philosophy

- **Pure Python is a constraint.** No C extensions. `cryptography` is the only runtime dep and it stays that way. "Faster if we compile it" dies the moment we compile something.
- **Sans-I/O or nothing.** The protocol layer consumes bytes and produces bytes. No sockets, no threads, no timers of its own. Callers drive the clock via `now=`. Load-bearing for testability and for running under any transport.
- **Frozen events, typed contracts.** Events are frozen dataclasses. Handlers are Protocols. `Any` does not belong in the public API.
- **Free-threading native.** CI runs with `PYTHON_GIL=0`. Shared mutable state is the enemy — assume no GIL, design accordingly.
- **Composition over abstraction.** Packet → Crypto → Stream → Connection → Recovery → H3. Each layer testable in isolation. Don't collapse them, don't add a ninth.
- **Sharp edges are bugs.** `except Exception: pass`, `contextlib.suppress` in `src/`, `load_*(...) or {}`, `type: ignore`, unhelpful errors — not taste, bugs. CI catches some (S110, S112, grep gates); the rest is on you.
- **RFCs are the spec.** When code disagrees with RFC 9000/9001/9002/9114, the RFC wins. Cite the section in the PR.

---

## Stakes

When you change something in Zoomies, the blast radius is:

- **Protocol bugs (QUIC/TLS/H3)** → wire-level corruption, silent data loss, request smuggling, connection resets under load. Debuggable only with packet captures. Harm: an end user's session gets crossed with someone else's, on a server they've never heard of.
- **Crypto bugs** → InvalidTag in the wrong place, key update mishandled, old keys retained past the window. Harm: decryption failures that look like network flakiness; worst case, a security regression.
- **Loss recovery / congestion bugs** → spurious retransmits, stuck PTOs, NewReno misbehavior. Harm: throughput collapse under real-world loss patterns that the loopback tests never see.
- **Free-threaded races** → no GIL safety net. Zoomies is on the 3.14t critical path for anyone consuming it — a race we ship normalizes "free-threading is flaky" for the whole ecosystem.
- **Public API changes** → Pounce and direct library users break. The surface is small on purpose; breakage is expensive.

Zoomies is beta but shipped, and Pounce sits downstream. Calibrate accordingly.

---

## Who reads your output

- **Pounce / b-stack maintainers** — need stable events and predictable state transitions. They read diffs and CHANGELOG.
- **Library users writing QUIC code** — know sans-I/O, not our internals. They read `__init__` exports, event names, and tracebacks.
- **Contributors** — know the RFCs, not our layering. They read protocol code and the connection state machine.
- **Me (Lawrence)** — read diffs. Put the what in code, the why in the PR. Cite RFC sections when relevant.

---

## Escape hatches — stop and ask

Forks where I want a check-in, not a judgment call:

- **New runtime dependency.** `cryptography` is the line. Ask.
- **Touching the hot path** (`datagram_received`, packet decrypt/parse, frame dispatch). Show before/after benchmarks. Can't measure → don't change.
- **Crypto / TLS state machine** (`crypto/tls.py`, key schedule, key update, 0-RTT acceptance). Sketch the change and ask before implementing.
- **Loss recovery / congestion control.** RFC 9002 is subtle. Cite the section, ask before rewriting.
- **Public API change** (`QuicConnection`, `QuicConfiguration`, event dataclasses, `H3Connection`, `RetryTokenHandler`). Ask whether the break is worth it. Frozen dataclass field renames count.
- **New event type or new config field.** Reshape an existing one first. Events and config are the contract with Pounce.
- **New layer or new abstraction.** H3 is real; H4 is not. Don't build for hypothetical protocols.
- **Dead code you found.** Flag in the PR, let me decide — it might be load-bearing for a handshake path or an RFC edge case that the tests don't hit.
- **Test disagrees with code.** Ask which is authoritative — and whether the RFC agrees with either — before "fixing" one.
- **Can't reproduce a reported bug.** Stop. Ask for a packet capture, a minimal repro, or an env dump. QUIC bugs do not yield to guessing.
- **Adjacent issues found mid-task.** List in the PR description. Don't fold them in — exception: a sharp-edges audit, where bundling is the point.

---

## Anti-patterns

Things that look reasonable and are wrong here:

- **C extensions "just for the hot path."** No. The whole point is pure Python on 3.14t.
- **`try: ... except Exception: pass`** or `except: continue`. S110/S112 are on in CI for a reason. If you must swallow, log what and why in one line — and expect to defend it in review.
- **`contextlib.suppress(...)` in `src/`**. The CI grep will catch you. Same rule as bare suppression: explicit log or don't swallow.
- **`load_*(...) or {}`** — masks a failing load as an empty dict. Fail loudly, or return a real default with a real reason.
- **`# type: ignore`.** Target is zero. Narrow the type or fix the code. If you have to, own it in the PR.
- **Speculative config options** for "future flexibility." `QuicConfiguration` is small because it's a contract. Don't add a field no one asked for.
- **Defensive validation inside internal code.** Validate at the boundary (`QuicConfiguration.__post_init__`, public entrypoints); internal code trusts its callers.
- **Using `now=0.0` or wall-clock time.** The API takes monotonic `now=`. `now=0.0` is a DeprecationWarning for a reason.
- **Mutable shared state without a clear owner.** Free-threading has no GIL. "It's probably fine" is not a thread-safety argument.
- **Refactoring during a bug fix.** Separate PR. Exception: a sharp-edges audit, where the refactor *is* the fix — but say so in the title.

---

## Done criteria

A change is done when all of these hold:

- [ ] `make lint`, `make format`, and `make ty` clean. No new `type: ignore`, no new S110/S112 suppressions, no new `contextlib.suppress` in `src/`.
- [ ] `make test` (or `poe test`) passes on 3.14t with `PYTHON_GIL=0`. Tests pass with the GIL off is the bar, not tests pass.
- [ ] Tests exercise the *interesting* path: client and server sides of a handshake, malformed/oversized/zero-length frames, key update mid-stream, loss and reordering for recovery changes, both `ZeroRttPolicy` branches when 0-RTT is in play.
- [ ] Hot-path changes include a benchmark in the PR. "Didn't benchmark" is OK only if you say why.
- [ ] GIL-sensitive? Note what you thought about on 3.14t — shared-mutable state, iteration-during-mutation, event ordering.
- [ ] Protocol change → cite the RFC section. If it contradicts the RFC, explain why.
- [ ] Public API changed → CHANGELOG entry, migration note if breaking, and a ping to Pounce if an event shape moves.
- [ ] Error messages tell the reader what to do next, not just what went wrong. "Invalid transport parameter" is a bug; "initial_max_data must be non-negative, got -1" is the bar.
- [ ] PR description explains *why*. The diff explains what.

"Tests pass" is not "done." Tests pass on broken code all the time, and QUIC tests pass on code that would corrupt bytes on a real network.

---

## Review and assimilation

- **I read diff-first, description-second.** Tight diff + clear why + RFC citation merges fast; sprawling diff gets questions.
- **One concern per PR.** If the diff needs section headers, it's two PRs. Exception: sharp-edges audits, where bundling related correctness fixes beats review churn — call it out in the title (`feat: Sharp-edges vN — ...`).
- **Commit style:** see `git log`. `feat:`/`fix:`/`ci:`/`refactor:`/`docs:`/`deps:`/`release:`/`test:`/`prep:` prefixes, imperative, body = motivation and RFC sections.
- **Don't trailing-summary me.** If the diff is readable, I can read it.
- **Flag surprises.** Weird test, unused event field, unreachable branch in the state machine, a TODO older than the repo — put it in the PR description. Don't fix silently, don't ignore.

---

## When this file is wrong

It will be. Tell me. The worst outcome is that it sits here for a year contradicting how the project actually works. Updates to AGENTS.md are a first-class PR — short, focused, and welcome.
