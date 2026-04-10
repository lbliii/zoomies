"""TLS 1.3 handshake adapter for QUIC (client and server).

Minimal implementation using cryptography primitives per RFC 8446.
Supports X25519 key exchange and ECDSA P-256 certificate auth.
"""

import os
import secrets
from dataclasses import dataclass
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding

from zoomies.crypto._hkdf import hkdf_expand_label, hkdf_extract
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
CLIENT_CONTEXT_STRING = b"TLS 1.3, client CertificateVerify"
EXT_SERVER_NAME = 0
QUIC_TP_EXT_TYPE = 0x0039  # RFC 9001 §8.2: QUIC transport parameters


class TlsHandshakeState(StrEnum):
    """TLS handshake state for QUIC server."""

    START = "start"
    CLIENT_HELLO_RECEIVED = "client_hello_received"
    HANDSHAKE_COMPLETE = "handshake_complete"
    CLOSED = "closed"


class ClientTlsState(StrEnum):
    """TLS handshake state for QUIC client."""

    START = "start"
    WAIT_SERVER_HELLO = "wait_server_hello"
    WAIT_ENCRYPTED_EXTENSIONS = "wait_encrypted_extensions"
    WAIT_CERTIFICATE = "wait_certificate"
    WAIT_CERTIFICATE_VERIFY = "wait_certificate_verify"
    WAIT_FINISHED = "wait_finished"
    HANDSHAKE_COMPLETE = "handshake_complete"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class TlsHandshakeResult:
    """Result of processing TLS handshake data."""

    state: TlsHandshakeState
    data_to_send: bytes
    handshake_secret: bytes | None = None
    traffic_secret: bytes | None = None


def _hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """HKDF-Expand-Label (RFC 8446 7.1) — SHA256 convenience wrapper."""
    return hkdf_expand_label(hashes.SHA256, secret, label, context, length)


def _hkdf_extract(salt: bytes, key_material: bytes) -> bytes:
    """HKDF-Extract — SHA256 convenience wrapper."""
    return hkdf_extract(hashes.SHA256, salt, key_material)


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
            except ValueError, BufferReadError:
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
                peer_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_data)
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
        server_hello = _build_server_hello(self._server_random, session_id, key_share)
        self._handshake_hash.update(server_hello)

        early_secret = _hkdf_extract(bytes(32), bytes(32))
        derived = _hkdf_expand_label(early_secret, b"derived", b"", 32)
        self._handshake_secret = _hkdf_extract(derived, shared)

        ee = _build_encrypted_extensions()
        self._handshake_hash.update(ee)

        cert_der = self._cert.public_bytes(Encoding.DER)
        cert_msg = _build_certificate(cert_der)
        self._handshake_hash.update(cert_msg)

        transcript_hash = self._handshake_hash.copy().finalize()
        verify_data = b" " * 64 + SERVER_CONTEXT_STRING + b"\x00" + transcript_hash
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            signature = self._key.sign(verify_data, ec.ECDSA(hashes.SHA256()))
            sig_alg = SIG_ECDSA_SECP256R1_SHA256
        else:
            raise ValueError("Unsupported private key type")
        cert_verify = _build_certificate_verify(sig_alg, signature)
        self._handshake_hash.update(cert_verify)

        s_hs_traffic = _hkdf_expand_label(
            self._handshake_secret, b"s hs traffic", transcript_hash, 32
        )
        fin_key = _hkdf_expand_label(s_hs_traffic, b"finished", b"", 32)
        h = hmac.HMAC(fin_key, hashes.SHA256())
        h.update(transcript_hash)
        verify_data_fin = h.finalize()
        finished = _build_finished(verify_data_fin)
        self._handshake_hash.update(finished)

        derived2 = _hkdf_expand_label(self._handshake_secret, b"derived", transcript_hash, 32)
        master_secret = _hkdf_extract(derived2, bytes(32))
        self._traffic_secret = _hkdf_expand_label(
            master_secret, b"s ap traffic", transcript_hash, 32
        )

        return server_hello + ee + cert_msg + cert_verify + finished

    def _handle_finished(self, msg: bytes) -> None:
        """Verify client Finished."""
        if self._handshake_secret is None:
            raise ValueError("Handshake secret not set")
        buf = Buffer(data=msg)
        if buf.pull_uint8() != HANDSHAKE_FINISHED:
            raise ValueError("Expected Finished")
        client_verify = _pull_block(buf, 3)
        c_hs_traffic = _hkdf_expand_label(
            self._handshake_secret, b"c hs traffic", self._handshake_hash.copy().finalize(), 32
        )
        fin_key = _hkdf_expand_label(c_hs_traffic, b"finished", b"", 32)
        h = hmac.HMAC(fin_key, hashes.SHA256())
        h.update(self._handshake_hash.copy().finalize())
        expected = h.finalize()
        if len(client_verify) != len(expected):
            raise ValueError("Finished verify failed")
        if not secrets.compare_digest(client_verify, expected):
            raise ValueError("Finished verify failed")
        self._handshake_hash.update(msg)


# ---------------------------------------------------------------------------
# Client-side TLS helpers
# ---------------------------------------------------------------------------


def _build_client_hello(
    random: bytes,
    session_id: bytes,
    key_share: tuple[int, bytes],
    server_name: str | None = None,
) -> bytes:
    """Build ClientHello message."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_CLIENT_HELLO)
    inner = Buffer()
    inner.push_uint16(TLS_VERSION_1_2)  # legacy version
    inner.push_bytes(random)
    _push_block(inner, 1, session_id)
    # Cipher suites
    cs_buf = Buffer()
    cs_buf.push_uint16(CIPHER_SUITE_AES_128_GCM)
    _push_block(inner, 2, cs_buf.data)
    # Compression methods
    _push_block(inner, 1, bytes([COMPRESSION_NULL]))
    # Extensions
    ext_buf = Buffer()
    # Supported versions (required for TLS 1.3)
    ext_buf.push_uint16(EXT_SUPPORTED_VERSIONS)
    sv_buf = Buffer()
    sv_buf.push_uint8(2)  # list length
    sv_buf.push_uint16(TLS_VERSION_1_3)
    ext_buf.push_uint16(len(sv_buf.data))
    ext_buf.push_bytes(sv_buf.data)
    # Supported groups
    ext_buf.push_uint16(EXT_SUPPORTED_GROUPS)
    sg_buf = Buffer()
    sg_buf.push_uint16(2)  # list length
    sg_buf.push_uint16(GROUP_X25519)
    ext_buf.push_uint16(len(sg_buf.data))
    ext_buf.push_bytes(sg_buf.data)
    # Signature algorithms
    ext_buf.push_uint16(EXT_SIGNATURE_ALGORITHMS)
    sa_buf = Buffer()
    sa_buf.push_uint16(2)  # list length
    sa_buf.push_uint16(SIG_ECDSA_SECP256R1_SHA256)
    ext_buf.push_uint16(len(sa_buf.data))
    ext_buf.push_bytes(sa_buf.data)
    # Key share
    ext_buf.push_uint16(EXT_KEY_SHARE)
    ks_buf = Buffer()
    entry = Buffer()
    entry.push_uint16(key_share[0])
    entry.push_uint16(len(key_share[1]))
    entry.push_bytes(key_share[1])
    ks_buf.push_uint16(len(entry.data))
    ks_buf.push_bytes(entry.data)
    ext_buf.push_uint16(len(ks_buf.data))
    ext_buf.push_bytes(ks_buf.data)
    # SNI (server name indication)
    if server_name:
        ext_buf.push_uint16(EXT_SERVER_NAME)
        sni_inner = Buffer()
        sni_list = Buffer()
        sni_list.push_uint8(0)  # host_name type
        name_bytes = server_name.encode("ascii")
        sni_list.push_uint16(len(name_bytes))
        sni_list.push_bytes(name_bytes)
        sni_inner.push_uint16(len(sni_list.data))
        sni_inner.push_bytes(sni_list.data)
        ext_buf.push_uint16(len(sni_inner.data))
        ext_buf.push_bytes(sni_inner.data)
    _push_block(inner, 2, ext_buf.data)
    _push_block(buf, 3, inner.data)
    return buf.data


def _parse_server_hello(data: bytes) -> tuple[bytes, bytes, tuple[int, bytes]]:
    """Parse ServerHello; return (random, legacy_session_id, key_share_entry)."""
    buf = Buffer(data=data)
    if buf.pull_uint8() != HANDSHAKE_SERVER_HELLO:
        raise ValueError("Expected ServerHello")
    payload = _pull_block(buf, 3)
    inner = Buffer(data=payload)
    if inner.pull_uint16() != TLS_VERSION_1_2:
        raise ValueError("ServerHello version")
    random = inner.pull_bytes(32)
    session_id = _pull_block(inner, 1)
    _cipher_suite = inner.pull_uint16()
    _compression = inner.pull_uint8()
    extensions: dict[int, bytes] = {}
    ext_data = _pull_block(inner, 2)
    ext_buf = Buffer(data=ext_data)
    while not ext_buf.eof():
        ext_type = ext_buf.pull_uint16()
        ext_len = ext_buf.pull_uint16()
        extensions[ext_type] = ext_buf.pull_bytes(ext_len)
    if EXT_KEY_SHARE not in extensions:
        raise ValueError("ServerHello missing key_share")
    ks_buf = Buffer(data=extensions[EXT_KEY_SHARE])
    group = ks_buf.pull_uint16()
    key_len = int.from_bytes(ks_buf.pull_bytes(2), "big")
    key_data = ks_buf.pull_bytes(key_len)
    return random, session_id, (group, key_data)


def _parse_encrypted_extensions(data: bytes) -> dict[int, bytes]:
    """Parse EncryptedExtensions; return extension map."""
    buf = Buffer(data=data)
    if buf.pull_uint8() != HANDSHAKE_ENCRYPTED_EXTENSIONS:
        raise ValueError("Expected EncryptedExtensions")
    payload = _pull_block(buf, 3)
    extensions: dict[int, bytes] = {}
    if payload:
        ext_buf = Buffer(data=payload)
        while not ext_buf.eof():
            ext_type = ext_buf.pull_uint16()
            ext_len = ext_buf.pull_uint16()
            extensions[ext_type] = ext_buf.pull_bytes(ext_len)
    return extensions


def _parse_certificate(data: bytes) -> list[bytes]:
    """Parse Certificate message; return list of DER-encoded certificates."""
    buf = Buffer(data=data)
    if buf.pull_uint8() != HANDSHAKE_CERTIFICATE:
        raise ValueError("Expected Certificate")
    payload = _pull_block(buf, 3)
    inner = Buffer(data=payload)
    _context = _pull_block(inner, 1)  # certificate_request_context
    certs_data = _pull_block(inner, 3)
    certs_buf = Buffer(data=certs_data)
    certs: list[bytes] = []
    while not certs_buf.eof():
        cert_der = _pull_block(certs_buf, 3)
        _extensions = _pull_block(certs_buf, 2)
        certs.append(cert_der)
    return certs


def _parse_certificate_verify(data: bytes) -> tuple[int, bytes]:
    """Parse CertificateVerify; return (algorithm, signature)."""
    buf = Buffer(data=data)
    if buf.pull_uint8() != HANDSHAKE_CERTIFICATE_VERIFY:
        raise ValueError("Expected CertificateVerify")
    payload = _pull_block(buf, 3)
    inner = Buffer(data=payload)
    algorithm = inner.pull_uint16()
    signature = _pull_block(inner, 2)
    return algorithm, signature


class QuicClientTlsContext:
    """TLS 1.3 context for QUIC client handshake."""

    def __init__(
        self,
        *,
        ca_certs: bytes | None = None,
        verify_mode: bool = True,
        server_name: str | None = None,
    ) -> None:
        self._ca_certs = ca_certs
        self._verify_mode = verify_mode
        self._server_name = server_name
        self._state = ClientTlsState.START
        self._receive_buffer = b""
        self._handshake_hash = hashes.Hash(hashes.SHA256())
        self._handshake_secret: bytes | None = None
        self._traffic_secret: bytes | None = None
        self._client_random = b""
        self._legacy_session_id = b""
        self._private_key: x25519.X25519PrivateKey | None = None
        self._server_cert_der: bytes | None = None
        # Transcript hash at CH+SH+EE+Cert — used for CertVerify, Finished, traffic keys
        self._transcript_at_cert: bytes | None = None

    @property
    def state(self) -> ClientTlsState:
        return self._state

    def build_client_hello(self) -> bytes:
        """Generate ClientHello message. Call once before receive()."""
        if self._state != ClientTlsState.START:
            raise RuntimeError("build_client_hello already called")
        self._client_random = os.urandom(32)
        self._legacy_session_id = os.urandom(32)
        self._private_key = x25519.X25519PrivateKey.generate()
        pub = self._private_key.public_key().public_bytes(
            Encoding.Raw, serialization.PublicFormat.Raw
        )
        msg = _build_client_hello(
            self._client_random,
            self._legacy_session_id,
            (GROUP_X25519, pub),
            server_name=self._server_name,
        )
        self._handshake_hash.update(msg)
        self._state = ClientTlsState.WAIT_SERVER_HELLO
        return msg

    def receive(self, data: bytes) -> TlsHandshakeResult:
        """Process incoming TLS handshake data from server."""
        self._receive_buffer += data
        to_send = b""

        while len(self._receive_buffer) >= 4:
            msg_type = self._receive_buffer[0]
            msg_len = int.from_bytes(self._receive_buffer[1:4], "big")
            total = 4 + msg_len
            if len(self._receive_buffer) < total:
                break
            msg = self._receive_buffer[:total]
            self._receive_buffer = self._receive_buffer[total:]

            if self._state == ClientTlsState.WAIT_SERVER_HELLO:
                if msg_type != HANDSHAKE_SERVER_HELLO:
                    raise ValueError(f"Expected ServerHello, got {msg_type}")
                self._handle_server_hello(msg)
            elif self._state == ClientTlsState.WAIT_ENCRYPTED_EXTENSIONS:
                if msg_type != HANDSHAKE_ENCRYPTED_EXTENSIONS:
                    raise ValueError(f"Expected EncryptedExtensions, got {msg_type}")
                self._handle_encrypted_extensions(msg)
            elif self._state == ClientTlsState.WAIT_CERTIFICATE:
                if msg_type != HANDSHAKE_CERTIFICATE:
                    raise ValueError(f"Expected Certificate, got {msg_type}")
                self._handle_certificate(msg)
            elif self._state == ClientTlsState.WAIT_CERTIFICATE_VERIFY:
                if msg_type != HANDSHAKE_CERTIFICATE_VERIFY:
                    raise ValueError(f"Expected CertificateVerify, got {msg_type}")
                self._handle_certificate_verify(msg)
            elif self._state == ClientTlsState.WAIT_FINISHED:
                if msg_type != HANDSHAKE_FINISHED:
                    raise ValueError(f"Expected Finished, got {msg_type}")
                to_send = self._handle_server_finished(msg)
            else:
                break

        return TlsHandshakeResult(
            state=TlsHandshakeState.HANDSHAKE_COMPLETE
            if self._state == ClientTlsState.HANDSHAKE_COMPLETE
            else TlsHandshakeState.START
            if self._state == ClientTlsState.WAIT_SERVER_HELLO
            else TlsHandshakeState.CLIENT_HELLO_RECEIVED,
            data_to_send=to_send,
            handshake_secret=self._handshake_secret,
            traffic_secret=self._traffic_secret,
        )

    def _handle_server_hello(self, msg: bytes) -> None:
        """Process ServerHello — derive handshake secret."""
        self._handshake_hash.update(msg)
        _random, _session_id, key_share = _parse_server_hello(msg)
        if self._private_key is None:
            raise RuntimeError("Client key not initialized")

        group, peer_pub_bytes = key_share
        if group == GROUP_X25519:
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
            shared = self._private_key.exchange(peer_public)
        else:
            raise ValueError(f"Unsupported key share group: {group}")

        early_secret = _hkdf_extract(bytes(32), bytes(32))
        derived = _hkdf_expand_label(early_secret, b"derived", b"", 32)
        self._handshake_secret = _hkdf_extract(derived, shared)
        self._state = ClientTlsState.WAIT_ENCRYPTED_EXTENSIONS

    def _handle_encrypted_extensions(self, msg: bytes) -> None:
        """Process EncryptedExtensions."""
        self._handshake_hash.update(msg)
        _extensions = _parse_encrypted_extensions(msg)
        self._state = ClientTlsState.WAIT_CERTIFICATE

    def _handle_certificate(self, msg: bytes) -> None:
        """Process Certificate — store server cert for verification."""
        self._handshake_hash.update(msg)
        # Save transcript hash at CH+SH+EE+Cert — matches server's transcript_hash
        self._transcript_at_cert = self._handshake_hash.copy().finalize()
        certs = _parse_certificate(msg)
        if not certs:
            raise ValueError("Empty certificate chain")
        self._server_cert_der = certs[0]
        if self._verify_mode:
            self._verify_certificate(certs)
        self._state = ClientTlsState.WAIT_CERTIFICATE_VERIFY

    def _verify_certificate(self, certs: list[bytes]) -> None:
        """Verify server certificate against CA certs."""
        if not self._ca_certs:
            raise ValueError("No CA certificates provided for verification")
        server_cert = x509.load_der_x509_certificate(certs[0])
        ca_certs_list = x509.load_pem_x509_certificates(self._ca_certs)
        # Verify the server cert was signed by one of the CA certs
        verified = False
        for ca_cert in ca_certs_list:
            try:
                ca_cert.public_key().verify(
                    server_cert.signature,
                    server_cert.tbs_certificate_bytes,
                    ec.ECDSA(server_cert.signature_hash_algorithm),
                )
                verified = True
                break
            except Exception:
                continue
        if not verified:
            raise ValueError("Server certificate verification failed")

    def _handle_certificate_verify(self, msg: bytes) -> None:
        """Process CertificateVerify — verify server signature."""
        if self._transcript_at_cert is None or self._server_cert_der is None:
            raise RuntimeError("Certificate not processed yet")
        algorithm, signature = _parse_certificate_verify(msg)
        # Verify using transcript at CH+SH+EE+Cert (before CertificateVerify)
        verify_data = b" " * 64 + SERVER_CONTEXT_STRING + b"\x00" + self._transcript_at_cert
        server_cert = x509.load_der_x509_certificate(self._server_cert_der)
        if algorithm == SIG_ECDSA_SECP256R1_SHA256:
            server_cert.public_key().verify(
                signature, verify_data, ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        self._handshake_hash.update(msg)
        self._state = ClientTlsState.WAIT_FINISHED

    def _handle_server_finished(self, msg: bytes) -> bytes:
        """Process server Finished — verify MAC, derive traffic secret, build client Finished."""
        if self._handshake_secret is None or self._transcript_at_cert is None:
            raise RuntimeError("Handshake secret or transcript not set")
        # The server uses transcript_hash at CH+SH+EE+Cert for everything:
        # s_hs_traffic, Finished MAC, derived2, traffic_secret.
        # We must match exactly.
        transcript_hash = self._transcript_at_cert

        # Verify server Finished
        buf = Buffer(data=msg)
        if buf.pull_uint8() != HANDSHAKE_FINISHED:
            raise ValueError("Expected Finished")
        server_verify = _pull_block(buf, 3)
        s_hs_traffic = _hkdf_expand_label(
            self._handshake_secret, b"s hs traffic", transcript_hash, 32
        )
        fin_key = _hkdf_expand_label(s_hs_traffic, b"finished", b"", 32)
        h = hmac.HMAC(fin_key, hashes.SHA256())
        h.update(transcript_hash)
        expected = h.finalize()
        if not secrets.compare_digest(server_verify, expected):
            raise ValueError("Server Finished verify failed")
        self._handshake_hash.update(msg)

        # Derive application traffic secret (matching server's derivation)
        derived2 = _hkdf_expand_label(self._handshake_secret, b"derived", transcript_hash, 32)
        master_secret = _hkdf_extract(derived2, bytes(32))
        self._traffic_secret = _hkdf_expand_label(
            master_secret, b"s ap traffic", transcript_hash, 32
        )

        # Build client Finished
        # Server verifies using hash at CH+SH+EE+Cert+CertVerify+ServerFinished
        transcript_for_client_fin = self._handshake_hash.copy().finalize()
        c_hs_traffic = _hkdf_expand_label(
            self._handshake_secret, b"c hs traffic", transcript_for_client_fin, 32
        )
        c_fin_key = _hkdf_expand_label(c_hs_traffic, b"finished", b"", 32)
        ch = hmac.HMAC(c_fin_key, hashes.SHA256())
        ch.update(transcript_for_client_fin)
        client_finished = _build_finished(ch.finalize())
        self._handshake_hash.update(client_finished)

        self._state = ClientTlsState.HANDSHAKE_COMPLETE
        return client_finished
