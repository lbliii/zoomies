"""Pytest configuration and shared fixtures for Zoomies tests."""

import os
import sys

# Add project root so "from tests.utils import ..." works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hypothesis import strategies as st

# Hypothesis strategies for round-trip fuzzing
st_varint = st.integers(min_value=0, max_value=2**62 - 1)
st_bytes = st.binary(max_size=4096)
