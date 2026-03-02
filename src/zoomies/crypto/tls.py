"""TLS 1.3 handshake adapter for QUIC (server-only).

Minimal implementation using cryptography primitives per RFC 8446.
Supports X25519 key exchange and ECDSA P-256 certificate auth.
"""

import os
import struct
from dataclasses import dataclass
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding

from zoomies.encoding import Buffer
from zoomies.encoding.buffer import BufferReadError

# TLS 1.3
TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304
CIPHER_SUITE_AES_128_GCM = 0x1301
COMPRESSION_NULL = 0
GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017
EXT_KEY_SHARE = 51
EXT_SUPPORTED_VERSIONS = 43
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_GROUPS = 10
SIG_ECDSA_SECP256R1_SHA256 = 0x0403
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_ENCRYPTED_EXTENSIONS = 8
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_CERTIFICATE_VERIFY = 15
HANDSHAKE_FINISHED = 20
SERVER_CONTEXT_STRING = b"TLS 1.3, server CertificateVerify"


class TlsHandshakeState(StrEnum):
    """TLS handshake state for QUIC server."""

    START = "start"
    CLIENT_HELLO_RECEIVED = "client_hello_received"
    HANDSHAKE_COMPLETE = "handshake_complete"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class TlsHandshakeResult:
    """Result of processing TLS handshake data."""

    state: TlsHandshakeState
    data_to_send: bytes
    handshake_secret: bytes | None = None
    traffic_secret: bytes | None = None


def _hkdf_label(label: bytes, context: bytes, length: int) -> bytes:
    """TLS 1.3 HKDF label (RFC 8446 7.1)."""
    full = b"tls13 " + label
    return (
        struct.pack("!HB", length, len(full))
        + full
        + struct.pack("!B", len(context))
        + context
    )


def _hkdf_expand_label(
    secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """HKDF-Expand-Label (RFC 8446 7.1)."""
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=_hkdf_label(label, context, length),
    ).derive(secret)


def _hkdf_extract(salt: bytes, key_material: bytes) -> bytes:
    """HKDF-Extract."""
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(key_material)
    return h.finalize()


def _pull_block(buf: Buffer, capacity: int) -> bytes:
    """Pull length-prefixed block."""
    length = int.from_bytes(buf.pull_bytes(capacity), "big")
    return buf.pull_bytes(length)


def _push_block(buf: Buffer, capacity: int, payload: bytes) -> None:
    """Push length-prefixed block."""
    buf.push_bytes(len(payload).to_bytes(capacity, "big"))
    buf.push_bytes(payload)


def _parse_client_hello(data: bytes) -> tuple[bytes, bytes, list[tuple[int, bytes]]]:
    """Parse ClientHello; return (random, legacy_session_id, key_share_entries)."""
    buf = Buffer(data=data)
    if buf.pull_uint8() != HANDSHAKE_CLIENT_HELLO:
        raise ValueError("Expected ClientHello")
    payload = _pull_block(buf, 3)
    inner = Buffer(data=payload)
    if inner.pull_uint16() != TLS_VERSION_1_2:
        raise ValueError("ClientHello version")
    random = inner.pull_bytes(32)
    session_id = _pull_block(inner, 1)
    _pull_block(inner, 2)
    _pull_block(inner, 1)
    extensions: dict[int, bytes] = {}
    ext_data = _pull_block(inner, 2)
    ext_buf = Buffer(data=ext_data)
    while not ext_buf.eof():
        ext_type = ext_buf.pull_uint16()
        ext_len = ext_buf.pull_uint16()
        extensions[ext_type] = ext_buf.pull_bytes(ext_len)
    key_share: list[tuple[int, bytes]] = []
    if EXT_KEY_SHARE in extensions:
        ks_buf = Buffer(data=extensions[EXT_KEY_SHARE])
        ks_len = ks_buf.pull_uint16()
        end = ks_buf.tell() + ks_len
        while ks_buf.tell() < end:
            group = ks_buf.pull_uint16()
            key_len = int.from_bytes(ks_buf.pull_bytes(2), "big")
            key_data = ks_buf.pull_bytes(key_len)
            key_share.append((group, key_data))
    return random, session_id, key_share


def _build_server_hello(
    random: bytes, legacy_session_id: bytes, key_share: tuple[int, bytes]
) -> bytes:
    """Build ServerHello message."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_SERVER_HELLO)
    inner = Buffer()
    inner.push_uint16(TLS_VERSION_1_2)
    inner.push_bytes(random)
    _push_block(inner, 1, legacy_session_id)
    inner.push_uint16(CIPHER_SUITE_AES_128_GCM)
    inner.push_uint8(COMPRESSION_NULL)
    ext_buf = Buffer()
    ext_buf.push_uint16(EXT_SUPPORTED_VERSIONS)
    ext_buf.push_uint16(2)
    ext_buf.push_uint16(TLS_VERSION_1_3)
    ext_buf.push_uint16(EXT_KEY_SHARE)
    key_payload = Buffer()
    key_payload.push_uint16(key_share[0])
    key_payload.push_uint16(len(key_share[1]))
    key_payload.push_bytes(key_share[1])
    ext_buf.push_uint16(len(key_payload.data))
    ext_buf.push_bytes(key_payload.data)
    _push_block(inner, 2, ext_buf.data)
    _push_block(buf, 3, inner.data)
    return buf.data


def _build_encrypted_extensions() -> bytes:
    """Build minimal EncryptedExtensions."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_ENCRYPTED_EXTENSIONS)
    _push_block(buf, 3, b"")
    return buf.data


def _build_certificate(cert_der: bytes) -> bytes:
    """Build Certificate message."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_CERTIFICATE)
    inner = Buffer()
    _push_block(inner, 1, b"")
    certs_buf = Buffer()
    _push_block(certs_buf, 3, cert_der)
    _push_block(certs_buf, 2, b"")
    _push_block(inner, 3, certs_buf.data)
    _push_block(buf, 3, inner.data)
    return buf.data


def _build_certificate_verify(algorithm: int, signature: bytes) -> bytes:
    """Build CertificateVerify message."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_CERTIFICATE_VERIFY)
    inner = Buffer()
    inner.push_uint16(algorithm)
    _push_block(inner, 2, signature)
    _push_block(buf, 3, inner.data)
    return buf.data


def _build_finished(verify_data: bytes) -> bytes:
    """Build Finished message."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_FINISHED)
    _push_block(buf, 3, verify_data)
    return buf.data


class QuicTlsContext:
    """TLS 1.3 context for QUIC server handshake."""

    def __init__(self, *, certificate: bytes, private_key: bytes) -> None:
        self._cert = x509.load_pem_x509_certificate(certificate)
        self._key = serialization.load_pem_private_key(private_key, password=None)
        self._state = TlsHandshakeState.START
        self._receive_buffer = b""
        self._handshake_hash = hashes.Hash(hashes.SHA256())
        self._handshake_secret: bytes | None = None
        self._traffic_secret: bytes | None = None
        self._client_random = b""
        self._server_random = b""
        self._legacy_session_id = b""

    @property
    def state(self) -> TlsHandshakeState:
        return self._state

    def receive(self, data: bytes) -> TlsHandshakeResult:
        """Process incoming TLS handshake data."""
        if not data and self._state == TlsHandshakeState.START:
            return TlsHandshakeResult(state=self._state, data_to_send=b"")

        self._receive_buffer += data
        if (
            self._state == TlsHandshakeState.START
            and len(self._receive_buffer) >= 1
            and self._receive_buffer[0] != HANDSHAKE_CLIENT_HELLO
        ):
            self._state = TlsHandshakeState.CLIENT_HELLO_RECEIVED
            return TlsHandshakeResult(state=self._state, data_to_send=b"")
        to_send = b""

        while len(self._receive_buffer) >= 4:
            msg_type = self._receive_buffer[0]
            msg_len = int.from_bytes(self._receive_buffer[1:4], "big")
            total = 4 + msg_len
            if len(self._receive_buffer) < total:
                break
            msg = self._receive_buffer[:total]
            self._receive_buffer = self._receive_buffer[total:]

            try:
                if self._state == TlsHandshakeState.START and msg_type == HANDSHAKE_CLIENT_HELLO:
                    out = self._handle_client_hello(msg)
                    to_send += out
                    self._state = TlsHandshakeState.CLIENT_HELLO_RECEIVED
                elif (
                    self._state == TlsHandshakeState.CLIENT_HELLO_RECEIVED
                    and msg_type == HANDSHAKE_FINISHED
                ):
                    self._handle_finished(msg)
                    self._state = TlsHandshakeState.HANDSHAKE_COMPLETE
                    return TlsHandshakeResult(
                        state=self._state,
                        data_to_send=to_send,
                        handshake_secret=self._handshake_secret,
                        traffic_secret=self._traffic_secret,
                    )
                else:
                    break
            except (ValueError, BufferReadError):
                if self._state == TlsHandshakeState.START:
                    self._state = TlsHandshakeState.CLIENT_HELLO_RECEIVED
                else:
                    self._state = TlsHandshakeState.CLOSED
                    raise
                break

        return TlsHandshakeResult(
            state=self._state,
            data_to_send=to_send,
            handshake_secret=self._handshake_secret,
            traffic_secret=self._traffic_secret,
        )

    def _handle_client_hello(self, msg: bytes) -> bytes:
        """Process ClientHello, return server response."""
        self._handshake_hash.update(msg)
        random, session_id, key_share_list = _parse_client_hello(msg)
        self._client_random = random
        self._legacy_session_id = session_id

        peer_public = None
        for group, key_data in key_share_list:
            if group == GROUP_X25519:
                peer_public = x25519.X25519PublicKey.from_public_bytes(key_data)
                break
            if group == GROUP_SECP256R1:
                peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), key_data
                )
                break
        if peer_public is None:
            raise ValueError("No supported key share")

        if isinstance(peer_public, x25519.X25519PublicKey):
            server_priv = x25519.X25519PrivateKey.generate()
            shared = server_priv.exchange(peer_public)
            server_pub = server_priv.public_key().public_bytes(
                Encoding.Raw, serialization.PublicFormat.Raw
            )
            key_share = (GROUP_X25519, server_pub)
        else:
            server_priv = ec.generate_private_key(ec.SECP256R1())
            shared = server_priv.exchange(ec.ECDH(), peer_public)
            server_pub = server_priv.public_key().public_bytes(
                Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            key_share = (GROUP_SECP256R1, server_pub)

        self._server_random = os.urandom(32)
        server_hello = _build_server_hello(
            self._server_random, session_id, key_share
        )
        self._handshake_hash.update(server_hello)

        early_secret = _hkdf_extract(bytes(32), bytes(32))
        derived = _hkdf_expand_label(
            early_secret, b"derived", b"", 32
        )
        self._handshake_secret = _hkdf_extract(derived, shared)

        ee = _build_encrypted_extensions()
        self._handshake_hash.update(ee)

        cert_der = self._cert.public_bytes(Encoding.DER)
        cert_msg = _build_certificate(cert_der)
        self._handshake_hash.update(cert_msg)

        transcript_hash = self._handshake_hash.copy().finalize()
        verify_data = (
            b" " * 64 + SERVER_CONTEXT_STRING + b"\x00" + transcript_hash
        )
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            signature = self._key.sign(
                verify_data, ec.ECDSA(hashes.SHA256())
            )
            sig_alg = SIG_ECDSA_SECP256R1_SHA256
        else:
            raise ValueError("Unsupported private key type")
        cert_verify = _build_certificate_verify(sig_alg, signature)
        self._handshake_hash.update(cert_verify)

        s_hs_traffic = _hkdf_expand_label(
            self._handshake_secret, b"s hs traffic", transcript_hash, 32
        )
        fin_key = _hkdf_expand_label(
            s_hs_traffic, b"finished", b"", 32
        )
        h = hmac.HMAC(fin_key, hashes.SHA256())
        h.update(transcript_hash)
        verify_data_fin = h.finalize()
        finished = _build_finished(verify_data_fin)
        self._handshake_hash.update(finished)

        derived2 = _hkdf_expand_label(
            self._handshake_secret, b"derived", transcript_hash, 32
        )
        master_secret = _hkdf_extract(derived2, bytes(32))
        self._traffic_secret = _hkdf_expand_label(
            master_secret, b"s ap traffic", transcript_hash, 32
        )

        return server_hello + ee + cert_msg + cert_verify + finished

    def _handle_finished(self, msg: bytes) -> None:
        """Verify client Finished."""
        buf = Buffer(data=msg)
        if buf.pull_uint8() != HANDSHAKE_FINISHED:
            raise ValueError("Expected Finished")
        client_verify = _pull_block(buf, 3)
        c_hs_traffic = _hkdf_expand_label(
            self._handshake_secret, b"c hs traffic",
            self._handshake_hash.copy().finalize(), 32
        )
        fin_key = _hkdf_expand_label(c_hs_traffic, b"finished", b"", 32)
        h = hmac.HMAC(fin_key, hashes.SHA256())
        h.update(self._handshake_hash.copy().finalize())
        expected = h.finalize()
        if client_verify != expected:
            raise ValueError("Finished verify failed")
        self._handshake_hash.update(msg)
