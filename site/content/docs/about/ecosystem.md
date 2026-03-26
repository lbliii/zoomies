---
title: The b-stack
description: How Zoomies fits into the Bengal ecosystem.
weight: 20
---

## Overview

Zoomies is part of the b-stack — a set of pure Python libraries built for free-threaded Python 3.14t. Each layer is standalone with no cross-dependencies.

| | Project | Role |
|--:|---------|------|
| **ᓚᘏᗢ** | [Bengal](https://github.com/lbliii/bengal) | Static site generator |
| **∿∿** | [Purr](https://github.com/lbliii/purr) | Content runtime |
| **⌁⌁** | [Chirp](https://github.com/lbliii/chirp) | Web framework |
| **=^..^=** | [Pounce](https://github.com/lbliii/pounce) | ASGI server |
| **)彡** | [Kida](https://github.com/lbliii/kida) | Template engine |
| **ฅᨐฅ** | [Patitas](https://github.com/lbliii/patitas) | Markdown parser |
| **⌾⌾⌾** | [Rosettes](https://github.com/lbliii/rosettes) | Syntax highlighter |
| **⟢⟣** | **Zoomies** | QUIC / HTTP/3 |

## How they connect

```
Request → Pounce (ASGI) → Chirp (routing) → Kida (templates)
  ↑                                            ↓
Zoomies (QUIC/H3)                    Patitas (markdown) + Rosettes (syntax)
```

Zoomies provides the transport layer. Pounce wraps it into an ASGI server. But Zoomies has **zero b-stack imports** — it works anywhere.

## Shared principles

- Pure Python, no C extensions (except `cryptography`)
- Free-threading native (3.14t)
- Typed with `py.typed` markers
- MIT licensed
