#!/usr/bin/env python3
"""Generate test fixtures (SSL certs) for Zoomies tests."""

import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

# Import from tests.utils (relative to project root)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tests.utils import generate_ec_certificate

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures")


def main() -> None:
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    cert, key = generate_ec_certificate(
        common_name="localhost",
        alternative_names=["localhost", "127.0.0.1", "::1"],
    )
    cert_path = os.path.join(FIXTURES_DIR, "ssl_cert.pem")
    key_path = os.path.join(FIXTURES_DIR, "ssl_key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption(),
            )
        )
    print(f"Generated {cert_path} and {key_path}")


if __name__ == "__main__":
    main()
