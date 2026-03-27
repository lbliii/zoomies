---
title: About
description: Architecture, design decisions, and the b-stack ecosystem
weight: 50
layout: list
menu:
  main:
    weight: 40
icon: info
---

# About

Zoomies is a sans-I/O protocol library for QUIC (RFC 9000) and HTTP/3 (RFC 9114),
written in pure Python for free-threaded Python 3.14t. It is part of the b-stack — a
set of composable libraries with no cross-dependencies.

## Why Zoomies?

| Benefit | What It Means |
|---------|---------------|
| **Sans-I/O** | Protocol layer consumes/produces bytes. No socket access. Caller owns I/O |
| **Free-Threading Native** | No C extensions with limited API. Uses only cryptography (3.14t-compatible) |
| **Typed** | Frozen dataclasses for events, Protocols for handlers. Full IDE support |
| **Composable** | Packet → Crypto → Stream → Connection → HTTP/3. Each layer testable in isolation |
| **Standards-Based** | RFC 9000, 9001, 9002, 9114. Loss recovery and congestion control included |

## Philosophy

Zoomies prioritizes **correctness over convenience**. The sans-I/O design means you
control the event loop, the socket, and the scheduling. The library handles protocol
state and nothing else.

---

:::{child-cards}
:columns: 2
:include: all
:fields: title, description, icon
:::
