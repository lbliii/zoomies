"""Test utilities — fixture loading, cert generation, Hypothesis helpers."""

import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def dns_name_or_ip_address(name: str) -> x509.GeneralName:
    """Convert string to GeneralName (DNS or IP)."""
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return x509.DNSName(name)
    return x509.IPAddress(ip)


def generate_certificate(
    *,
    alternative_names: list[str],
    common_name: str,
    hash_algorithm: hashes.HashAlgorithm | None,
    key: ec.EllipticCurvePrivateKey,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Generate a self-signed certificate."""
    subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=10))
    )
    if alternative_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([dns_name_or_ip_address(n) for n in alternative_names]),
            critical=False,
        )
    cert = builder.sign(key, hash_algorithm or hashes.SHA256())
    return cert, key


def generate_ec_certificate(
    common_name: str,
    alternative_names: list[str] | None = None,
    curve: type[ec.EllipticCurve] = ec.SECP256R1,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Generate EC certificate for tests."""
    key = ec.generate_private_key(curve=curve())
    return generate_certificate(
        alternative_names=alternative_names or [],
        common_name=common_name,
        hash_algorithm=hashes.SHA256(),
        key=key,
    )


def load(name: str) -> bytes:
    """Load fixture file from tests/ directory."""
    path = os.path.join(os.path.dirname(__file__), name)
    with open(path, "rb") as fp:
        return fp.read()


# Fixture paths
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SERVER_CERTFILE = os.path.join(FIXTURES_DIR, "ssl_cert.pem")
SERVER_KEYFILE = os.path.join(FIXTURES_DIR, "ssl_key.pem")
