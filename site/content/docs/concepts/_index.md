---
title: Concepts
description: Core ideas behind Zoomies — sans-I/O, QUIC connections, HTTP/3, and free-threading
weight: 20
icon: lightbulb
---

# Concepts

Understand the design decisions and protocol concepts that shape Zoomies. Each concept maps to a layer in the protocol stack.

## What Do You Need?

:::{child-cards}
:columns: 2
:include: all
:fields: title, description, icon
:::

## How the Layers Fit

| Layer | Concept | RFC |
|-------|---------|-----|
| **Packet** | Encoding, decoding, header protection | RFC 9000 §17 |
| **Crypto** | TLS 1.3 handshake, key derivation | RFC 9001 |
| **Stream** | Multiplexed, ordered byte streams | RFC 9000 §2 |
| **Connection** | State machine, loss recovery, congestion control | RFC 9000, 9002 |
| **HTTP/3** | QPACK, request/response, server push | RFC 9114 |

:::{tip}
**New to QUIC?** Start with [Sans-I/O](./sans-io/) to understand how Zoomies separates protocol logic from I/O, then read [Connection Lifecycle](./connection-lifecycle/) for the full state machine.
:::
