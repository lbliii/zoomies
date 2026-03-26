---
title: Installation
description: Install Zoomies with pip or uv.
weight: 10
---

## Requirements

- Python 3.14+ (free-threaded 3.14t recommended)
- `cryptography` >= 42.0.0 (installed automatically)

## Install

::::{tabs}

:::{tab} uv
```bash
uv add bengal-zoomies
```
:::

:::{tab} pip
```bash
pip install bengal-zoomies
```
:::

:::{tab} From source
```bash
git clone https://github.com/lbliii/zoomies.git
cd zoomies
uv sync --group dev
```
:::

::::

## Verify

```python
import zoomies
print(zoomies.__version__)
```
