---
title: Documentation
draft: false
weight: 5
lang: en
type: doc
cascade:
  type: doc
  variant: standard
category: documentation
description: Guides for using Zoomies — a sans-I/O QUIC and HTTP/3 library for free-threaded Python
keywords:
- zoomies
- quic
- http3
- python
- sans-io
- free-threading
menu:
  main:
    weight: 10
tags:
- documentation
- docs
variant: overview
icon: book-open
---

# Documentation

## Start Here

New to Zoomies? Start here to build QUIC and HTTP/3 applications in pure Python.
Zoomies covers the full protocol stack: TLS 1.3 handshake, loss recovery, congestion
control, stream multiplexing, and HTTP/3 — all sans-I/O and free-threading native.

::::{cards}
:columns: 2
:gap: medium

::::{card} Get Started
:icon: rocket
:link: ./get-started/
:description: Install Zoomies and parse your first QUIC packet
::::{/card}

::::{card} Tutorials
:icon: graduation-cap
:link: ./tutorials/
:description: Step-by-step guides for real protocol work
::::{/card}

::::{/cards}

## Understand

Learn the design decisions and protocol concepts that shape Zoomies.

::::{cards}
:columns: 2
:gap: medium

::::{card} Sans-I/O Pattern
:icon: cpu
:link: ./concepts/sans-io/
:description: How Zoomies separates protocol logic from I/O
::::{/card}

::::{card} Connection Lifecycle
:icon: arrows-clockwise
:link: ./concepts/connection-lifecycle/
:description: Handshake, streams, loss recovery, and close
::::{/card}

::::{card} HTTP/3
:icon: globe
:link: ./concepts/http3/
:description: H3Connection, QPACK, and request/response handling
::::{/card}

::::{card} Free-Threading
:icon: zap
:link: ./concepts/free-threading/
:description: Running Zoomies with Python 3.14t (no GIL)
::::{/card}

::::{/cards}

## Look It Up

Technical specifications, API surface, architecture details, and project background.

::::{cards}
:columns: 2
:gap: medium

::::{card} Reference
:icon: list-magnifying-glass
:link: ./reference/
:description: API surface, events, configuration, and types
::::{/card}

::::{card} About
:icon: info
:link: ./about/
:description: Architecture, design decisions, and the b-stack
::::{/card}

::::{/cards}
