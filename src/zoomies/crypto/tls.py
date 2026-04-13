"""TLS 1.3 handshake adapter for QUIC (client and server).

Minimal implementation using cryptography primitives per RFC 8446.
Supports X25519 key exchange and ECDSA P-256 certificate auth.
"""

import os
import secrets
import time
from dataclasses import dataclass, field
from enum import StrEnum

from cryptography import x509
from cryptography.exceptions import InvalidSignature
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
HANDSHAKE_NEW_SESSION_TICKET = 4
SERVER_CONTEXT_STRING = b"TLS 1.3, server CertificateVerify"
CLIENT_CONTEXT_STRING = b"TLS 1.3, client CertificateVerify"
EXT_SERVER_NAME = 0
EXT_PRE_SHARED_KEY = 41
EXT_EARLY_DATA = 42
EXT_PSK_KEY_EXCHANGE_MODES = 45
QUIC_TP_EXT_TYPE = 0x0039  # RFC 9001 §8.2: QUIC transport parameters
PSK_DHE_KE = 1  # RFC 8446 §4.2.9: PSK with (EC)DHE key exchange


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
    session_tickets: tuple[SessionTicket, ...] = ()
    early_secret: bytes | None = None
    client_hello_hash: bytes | None = None
    is_psk: bool = False
    early_data_accepted: bool = False
    psk_ticket_data: bytes | None = None
    psk_obfuscated_age: int = 0


@dataclass(frozen=True, slots=True)
class SessionTicket:
    """Opaque session ticket for TLS 1.3 resumption and 0-RTT.

    Issued by server after handshake via NewSessionTicket message.
    Client stores and presents on reconnection via
    ``QuicConfiguration.session_ticket``.

    **Limitations**: Tickets contain an in-memory random nonce and the
    resumption secret in plaintext. They are NOT stateless encrypted tokens.
    This means:

    - Tickets are only valid for the server process that issued them.
    - Multi-instance deployments require a shared ticket store or a custom
      ticket encryption layer (not provided by Zoomies).
    - Tickets do not survive server restarts unless serialized by the caller.
    - The caller is responsible for enforcing ticket lifetime and single-use
      semantics to prevent replay attacks.
    """

    ticket: bytes
    resumption_secret: bytes
    max_early_data: int = 0xFFFFFFFF
    cipher_suite: int = CIPHER_SUITE_AES_128_GCM
    timestamp: float = 0.0
    lifetime: int = 7200
    age_add: int = 0
    nonce: bytes = b""

    def derive_psk(self) -> bytes:
        """Derive PSK from resumption secret and nonce (RFC 8446 §4.6.1)."""
        return _hkdf_expand_label(self.resumption_secret, b"resumption", self.nonce, 32)


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


@dataclass(frozen=True, slots=True)
class _ClientHelloInfo:
    """Parsed ClientHello fields."""

    random: bytes
    session_id: bytes
    key_share: list[tuple[int, bytes]]
    extensions: dict[int, bytes] = field(default_factory=dict)


def _parse_client_hello(data: bytes) -> tuple[bytes, bytes, list[tuple[int, bytes]]]:
    """Parse ClientHello; return (random, legacy_session_id, key_share_entries)."""
    info = _parse_client_hello_full(data)
    return info.random, info.session_id, info.key_share


def _parse_client_hello_full(data: bytes) -> _ClientHelloInfo:
    """Parse ClientHello with all extensions."""
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
    return _ClientHelloInfo(
        random=random,
        session_id=session_id,
        key_share=key_share,
        extensions=extensions,
    )


def _build_server_hello(
    random: bytes,
    legacy_session_id: bytes,
    key_share: tuple[int, bytes],
    psk_identity: int | None = None,
) -> bytes:
    """Build ServerHello message.

    If psk_identity is set, includes pre_shared_key extension selecting that identity.
    """
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
    if psk_identity is not None:
        ext_buf.push_uint16(EXT_PRE_SHARED_KEY)
        ext_buf.push_uint16(2)
        ext_buf.push_uint16(psk_identity)
    _push_block(inner, 2, ext_buf.data)
    _push_block(buf, 3, inner.data)
    return buf.data


def _build_encrypted_extensions(*, early_data: bool = False) -> bytes:
    """Build EncryptedExtensions, optionally including early_data acceptance."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_ENCRYPTED_EXTENSIONS)
    if early_data:
        ext_buf = Buffer()
        ext_buf.push_uint16(EXT_EARLY_DATA)
        ext_buf.push_uint16(0)  # empty extension value = accepted
        _push_block(buf, 3, ext_buf.data)
    else:
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


def _build_new_session_ticket(
    lifetime: int,
    age_add: int,
    nonce: bytes,
    ticket: bytes,
    max_early_data: int = 0xFFFFFFFF,
) -> bytes:
    """Build NewSessionTicket message (RFC 8446 §4.6.1)."""
    buf = Buffer()
    buf.push_uint8(HANDSHAKE_NEW_SESSION_TICKET)
    inner = Buffer()
    inner.push_uint32(lifetime)
    inner.push_uint32(age_add)
    _push_block(inner, 1, nonce)
    _push_block(inner, 2, ticket)
    # Extensions — early_data extension with max_early_data_size
    ext_buf = Buffer()
    ext_buf.push_uint16(EXT_EARLY_DATA)
    ext_buf.push_uint16(4)
    ext_buf.push_uint32(max_early_data)
    _push_block(inner, 2, ext_buf.data)
    _push_block(buf, 3, inner.data)
    return buf.data


def _parse_new_session_ticket(data: bytes) -> tuple[int, int, bytes, bytes, int]:
    """Parse NewSessionTicket; return (lifetime, age_add, nonce, ticket, max_early_data)."""
    buf = Buffer(data=data)
    if buf.pull_uint8() != HANDSHAKE_NEW_SESSION_TICKET:
        raise ValueError("Expected NewSessionTicket")
    payload = _pull_block(buf, 3)
    inner = Buffer(data=payload)
    lifetime = inner.pull_uint32()
    age_add = inner.pull_uint32()
    nonce = _pull_block(inner, 1)
    ticket = _pull_block(inner, 2)
    max_early_data = 0
    if not inner.eof():
        ext_data = _pull_block(inner, 2)
        ext_buf = Buffer(data=ext_data)
        while not ext_buf.eof():
            ext_type = ext_buf.pull_uint16()
            ext_len = ext_buf.pull_uint16()
            ext_val = ext_buf.pull_bytes(ext_len)
            if ext_type == EXT_EARLY_DATA and ext_len >= 4:
                max_early_data = int.from_bytes(ext_val[:4], "big")
    return lifetime, age_add, nonce, ticket, max_early_data


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
        self._master_secret: bytes | None = None
        self._resumption_secret: bytes | None = None
        self._is_psk: bool = False
        self._early_secret: bytes | None = None
        self._client_hello_hash: bytes | None = None
        self._psk_ticket_data: bytes | None = None
        self._psk_obfuscated_age: int = 0
        # PSK state for session ticket validation
        self._session_tickets: list[SessionTicket] = []
        self._ticket_nonce_counter: int = 0
        # Set by connection layer to include early_data in EncryptedExtensions
        self.accept_early_data: bool = False

    @property
    def state(self) -> TlsHandshakeState:
        return self._state

    def add_session_ticket(self, ticket: SessionTicket) -> None:
        """Register a session ticket for PSK validation on future connections."""
        self._session_tickets.append(ticket)

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
                        is_psk=self._is_psk,
                        early_secret=self._early_secret,
                        client_hello_hash=self._client_hello_hash,
                        psk_ticket_data=self._psk_ticket_data,
                        psk_obfuscated_age=self._psk_obfuscated_age,
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
            is_psk=self._is_psk,
            early_secret=self._early_secret,
            client_hello_hash=self._client_hello_hash,
            psk_ticket_data=self._psk_ticket_data,
            psk_obfuscated_age=self._psk_obfuscated_age,
        )

    def _handle_client_hello(self, msg: bytes) -> bytes:
        """Process ClientHello, return server response.

        Supports both full handshake and PSK resumption (RFC 8446 §4.2.11).
        """
        self._handshake_hash.update(msg)
        # Capture transcript hash after just CH — needed for 0-RTT key derivation
        self._client_hello_hash = self._handshake_hash.copy().finalize()
        ch_info = _parse_client_hello_full(msg)
        self._client_random = ch_info.random
        self._legacy_session_id = ch_info.session_id

        # Check for PSK resumption
        psk: bytes | None = None
        psk_identity_index: int | None = None
        if EXT_PRE_SHARED_KEY in ch_info.extensions and self._session_tickets:
            psk, psk_identity_index, self._psk_ticket_data, self._psk_obfuscated_age = (
                self._try_validate_psk(msg, ch_info)
            )

        # Key exchange (always required — psk_dhe_ke mode)
        peer_public = None
        for group, key_data in ch_info.key_share:
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
        server_hello = _build_server_hello(
            self._server_random,
            ch_info.session_id,
            key_share,
            psk_identity=psk_identity_index,
        )
        self._handshake_hash.update(server_hello)

        # Key schedule — use real PSK if available, else zero
        psk_input = psk if psk is not None else bytes(32)
        early_secret = _hkdf_extract(bytes(32), psk_input)
        self._early_secret = early_secret
        self._is_psk = psk is not None
        derived = _hkdf_expand_label(early_secret, b"derived", b"", 32)
        self._handshake_secret = _hkdf_extract(derived, shared)

        include_early_data = psk is not None and self.accept_early_data
        ee = _build_encrypted_extensions(early_data=include_early_data)
        self._handshake_hash.update(ee)

        if psk is not None:
            # PSK mode: skip Certificate and CertificateVerify
            transcript_hash = self._handshake_hash.copy().finalize()
        else:
            # Full handshake: send Certificate + CertificateVerify
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
        self._master_secret = _hkdf_extract(derived2, bytes(32))
        self._traffic_secret = _hkdf_expand_label(
            self._master_secret, b"s ap traffic", transcript_hash, 32
        )

        if psk is not None:
            return server_hello + ee + finished
        return server_hello + ee + cert_msg + cert_verify + finished

    def _try_validate_psk(
        self, msg: bytes, ch_info: _ClientHelloInfo
    ) -> tuple[bytes | None, int | None, bytes | None, int]:
        """Try to validate PSK from ClientHello.

        Returns (psk, identity_index, ticket_data, obfuscated_age) or (None, None, None, 0).
        """
        psk_ext = ch_info.extensions[EXT_PRE_SHARED_KEY]
        psk_buf = Buffer(data=psk_ext)

        # Parse identities
        identities_data = _pull_block(psk_buf, 2)
        id_buf = Buffer(data=identities_data)
        identities: list[tuple[bytes, int]] = []
        while not id_buf.eof():
            identity = _pull_block(id_buf, 2)
            obfuscated_age = id_buf.pull_uint32()
            identities.append((identity, obfuscated_age))

        # Parse binders
        binders_data = _pull_block(psk_buf, 2)
        binder_buf = Buffer(data=binders_data)
        binders: list[bytes] = []
        while not binder_buf.eof():
            binder = _pull_block(binder_buf, 1)
            binders.append(binder)

        if len(identities) != len(binders):
            return None, None, None, 0

        # Try each identity against our known tickets
        for idx, (identity, obfuscated_age) in enumerate(identities):
            for ticket in self._session_tickets:
                if identity == ticket.ticket:
                    # Validate binder
                    psk = ticket.derive_psk()
                    early_secret = _hkdf_extract(bytes(32), psk)
                    binder_key = _hkdf_expand_label(early_secret, b"res binder", b"", 32)

                    # RFC 8446 §4.2.11.2: partial ClientHello is "up to and including
                    # the PreSharedKeyExtension.identities field" — i.e. we exclude
                    # the binders list length prefix (2 bytes) and binder entries.
                    binders_len = 2 + len(binders_data)
                    truncated_ch = msg[: len(msg) - binders_len]
                    truncated_hash = hashes.Hash(hashes.SHA256())
                    truncated_hash.update(truncated_ch)
                    h = hmac.HMAC(binder_key, hashes.SHA256())
                    h.update(truncated_hash.finalize())
                    expected_binder = h.finalize()

                    if secrets.compare_digest(binders[idx], expected_binder):
                        return psk, idx, identity, obfuscated_age

        return None, None, None, 0

    def _handle_finished(self, msg: bytes) -> None:
        """Verify client Finished and derive resumption_master_secret."""
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

        # Derive resumption_master_secret (RFC 8446 §7.1)
        if self._master_secret is not None:
            transcript_hash = self._handshake_hash.copy().finalize()
            self._resumption_secret = _hkdf_expand_label(
                self._master_secret, b"res master", transcript_hash, 32
            )

    def generate_session_ticket(self, lifetime: int = 7200) -> tuple[bytes, SessionTicket]:
        """Generate a NewSessionTicket message and corresponding SessionTicket.

        Returns (nst_message_bytes, session_ticket).
        Call after handshake is complete.

        .. warning::
            The returned ``SessionTicket`` contains the resumption secret in
            plaintext. It is only valid for this server process. See
            ``SessionTicket`` class docstring for multi-instance limitations.
        """
        if self._resumption_secret is None:
            raise RuntimeError("Handshake not complete — no resumption secret")

        nonce = self._ticket_nonce_counter.to_bytes(4, "big")
        self._ticket_nonce_counter += 1
        age_add = int.from_bytes(os.urandom(4), "big")

        # Ticket is opaque — for now just use a random identifier.
        # In production, the server would encrypt state into this.
        ticket_data = os.urandom(32)

        nst_msg = _build_new_session_ticket(
            lifetime=lifetime,
            age_add=age_add,
            nonce=nonce,
            ticket=ticket_data,
        )

        ticket = SessionTicket(
            ticket=ticket_data,
            resumption_secret=self._resumption_secret,
            lifetime=lifetime,
            age_add=age_add,
            nonce=nonce,
            timestamp=time.monotonic(),
        )
        return nst_msg, ticket


# ---------------------------------------------------------------------------
# Client-side TLS helpers
# ---------------------------------------------------------------------------


def _build_client_hello(
    random: bytes,
    session_id: bytes,
    key_share: tuple[int, bytes],
    server_name: str | None = None,
    session_ticket: SessionTicket | None = None,
) -> bytes:
    """Build ClientHello message.

    If session_ticket is provided, includes pre_shared_key and psk_key_exchange_modes
    extensions for PSK resumption. The PSK binder is computed and inserted.
    """
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
    # PSK extensions (must be last — RFC 8446 §4.2.11)
    if session_ticket is not None:
        # psk_key_exchange_modes
        ext_buf.push_uint16(EXT_PSK_KEY_EXCHANGE_MODES)
        psk_modes = Buffer()
        psk_modes.push_uint8(1)  # length of modes list
        psk_modes.push_uint8(PSK_DHE_KE)
        ext_buf.push_uint16(len(psk_modes.data))
        ext_buf.push_bytes(psk_modes.data)

        # pre_shared_key (must be LAST extension)
        psk = session_ticket.derive_psk()
        obfuscated_age = (
            int((time.monotonic() - session_ticket.timestamp) * 1000) + session_ticket.age_add
        ) & 0xFFFFFFFF

        # Build identities
        id_buf = Buffer()
        _push_block(id_buf, 2, session_ticket.ticket)
        id_buf.push_uint32(obfuscated_age)
        identities_data = id_buf.data

        # Placeholder binder (32 bytes for SHA-256)
        binder_placeholder = bytes(32)
        binder_entry = Buffer()
        _push_block(binder_entry, 1, binder_placeholder)
        binders_data = binder_entry.data

        # Build PSK extension with placeholder
        psk_ext = Buffer()
        _push_block(psk_ext, 2, identities_data)
        _push_block(psk_ext, 2, binders_data)
        ext_buf.push_uint16(EXT_PRE_SHARED_KEY)
        ext_buf.push_uint16(len(psk_ext.data))
        ext_buf.push_bytes(psk_ext.data)

    _push_block(inner, 2, ext_buf.data)
    _push_block(buf, 3, inner.data)
    msg = buf.data

    # Compute and insert real PSK binder
    if session_ticket is not None:
        psk = session_ticket.derive_psk()
        early_secret = _hkdf_extract(bytes(32), psk)
        binder_key = _hkdf_expand_label(early_secret, b"res binder", b"", 32)

        # RFC 8446 §4.2.11.2: partial ClientHello is "up to and including
        # the PreSharedKeyExtension.identities field" — we exclude the
        # binders list length prefix (2 bytes) and binder entries.
        binders_len = 2 + len(binders_data)
        truncated_ch = msg[: len(msg) - binders_len]
        truncated_hash = hashes.Hash(hashes.SHA256())
        truncated_hash.update(truncated_ch)
        h = hmac.HMAC(binder_key, hashes.SHA256())
        h.update(truncated_hash.finalize())
        real_binder = h.finalize()

        # Replace placeholder binder in the message
        # The binder is at: end - len(binder_placeholder) = end - 32
        msg = msg[: len(msg) - 32] + real_binder

    return msg


@dataclass(frozen=True, slots=True)
class _ServerHelloInfo:
    """Parsed ServerHello fields."""

    random: bytes
    session_id: bytes
    key_share: tuple[int, bytes]
    psk_identity: int | None = None


def _parse_server_hello(data: bytes) -> tuple[bytes, bytes, tuple[int, bytes]]:
    """Parse ServerHello; return (random, legacy_session_id, key_share_entry)."""
    info = _parse_server_hello_full(data)
    return info.random, info.session_id, info.key_share


def _parse_server_hello_full(data: bytes) -> _ServerHelloInfo:
    """Parse ServerHello with all extensions."""
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
    psk_identity = None
    if EXT_PRE_SHARED_KEY in extensions:
        psk_buf = Buffer(data=extensions[EXT_PRE_SHARED_KEY])
        psk_identity = psk_buf.pull_uint16()
    return _ServerHelloInfo(
        random=random,
        session_id=session_id,
        key_share=(group, key_data),
        psk_identity=psk_identity,
    )


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
        session_ticket: SessionTicket | None = None,
    ) -> None:
        self._ca_certs = ca_certs
        self._verify_mode = verify_mode
        self._server_name = server_name
        self._session_ticket = session_ticket
        self._state = ClientTlsState.START
        self._receive_buffer = b""
        self._handshake_hash = hashes.Hash(hashes.SHA256())
        self._handshake_secret: bytes | None = None
        self._traffic_secret: bytes | None = None
        self._master_secret: bytes | None = None
        self._resumption_secret: bytes | None = None
        self._early_secret: bytes | None = None
        self._client_hello_hash: bytes | None = None
        self._is_psk: bool = False
        self._early_data_accepted: bool = False
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
            session_ticket=self._session_ticket,
        )
        self._handshake_hash.update(msg)
        # Capture transcript hash after just CH — needed for 0-RTT key derivation
        self._client_hello_hash = self._handshake_hash.copy().finalize()
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

        # After handshake completes, parse any NewSessionTicket messages
        tickets: list[SessionTicket] = []
        if self._state == ClientTlsState.HANDSHAKE_COMPLETE:
            while len(self._receive_buffer) >= 4:
                nst_type = self._receive_buffer[0]
                nst_len = int.from_bytes(self._receive_buffer[1:4], "big")
                nst_total = 4 + nst_len
                if len(self._receive_buffer) < nst_total:
                    break
                nst_msg = self._receive_buffer[:nst_total]
                if nst_type != HANDSHAKE_NEW_SESSION_TICKET:
                    break  # Not a NST — leave in buffer for future handling
                self._receive_buffer = self._receive_buffer[nst_total:]
                tickets.append(self.receive_new_session_ticket(nst_msg))

        return TlsHandshakeResult(
            state=TlsHandshakeState.HANDSHAKE_COMPLETE
            if self._state == ClientTlsState.HANDSHAKE_COMPLETE
            else TlsHandshakeState.START
            if self._state == ClientTlsState.WAIT_SERVER_HELLO
            else TlsHandshakeState.CLIENT_HELLO_RECEIVED,
            data_to_send=to_send,
            handshake_secret=self._handshake_secret,
            traffic_secret=self._traffic_secret,
            session_tickets=tuple(tickets),
            is_psk=self._is_psk,
            early_secret=self._early_secret,
            client_hello_hash=self._client_hello_hash,
            early_data_accepted=self._early_data_accepted,
        )

    def _handle_server_hello(self, msg: bytes) -> None:
        """Process ServerHello — derive handshake secret."""
        self._handshake_hash.update(msg)
        sh_info = _parse_server_hello_full(msg)
        if self._private_key is None:
            raise RuntimeError("Client key not initialized")

        group, peer_pub_bytes = sh_info.key_share
        if group == GROUP_X25519:
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
            shared = self._private_key.exchange(peer_public)
        else:
            raise ValueError(f"Unsupported key share group: {group}")

        # PSK mode: use real PSK if server selected our identity
        psk_input = bytes(32)
        if (
            sh_info.psk_identity is not None
            and self._session_ticket is not None
            and sh_info.psk_identity == 0
        ):
            psk_input = self._session_ticket.derive_psk()
            self._is_psk = True

        early_secret = _hkdf_extract(bytes(32), psk_input)
        self._early_secret = early_secret
        derived = _hkdf_expand_label(early_secret, b"derived", b"", 32)
        self._handshake_secret = _hkdf_extract(derived, shared)
        self._state = ClientTlsState.WAIT_ENCRYPTED_EXTENSIONS

    def _handle_encrypted_extensions(self, msg: bytes) -> None:
        """Process EncryptedExtensions."""
        self._handshake_hash.update(msg)
        extensions = _parse_encrypted_extensions(msg)
        self._early_data_accepted = EXT_EARLY_DATA in extensions
        if self._is_psk:
            # PSK mode: no Certificate or CertificateVerify — go straight to Finished
            self._transcript_at_cert = self._handshake_hash.copy().finalize()
            self._state = ClientTlsState.WAIT_FINISHED
        else:
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
                pub = ca_cert.public_key()
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    continue
                hash_alg = server_cert.signature_hash_algorithm
                if hash_alg is None:
                    continue
                pub.verify(
                    server_cert.signature,
                    server_cert.tbs_certificate_bytes,
                    ec.ECDSA(hash_alg),
                )
                verified = True
                break
            except InvalidSignature, ValueError:
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
            pub = server_cert.public_key()
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise ValueError("Expected ECDSA key for signature verification")
            pub.verify(signature, verify_data, ec.ECDSA(hashes.SHA256()))
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
        self._master_secret = _hkdf_extract(derived2, bytes(32))
        self._traffic_secret = _hkdf_expand_label(
            self._master_secret, b"s ap traffic", transcript_hash, 32
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

        # Derive resumption_master_secret
        res_transcript = self._handshake_hash.copy().finalize()
        self._resumption_secret = _hkdf_expand_label(
            self._master_secret, b"res master", res_transcript, 32
        )

        self._state = ClientTlsState.HANDSHAKE_COMPLETE
        return client_finished

    def receive_new_session_ticket(self, data: bytes) -> SessionTicket:
        """Process a NewSessionTicket message from the server.

        Call after handshake is complete, when the server sends a ticket
        in the 1-RTT epoch.
        """
        if self._resumption_secret is None:
            raise RuntimeError("Handshake not complete — no resumption secret")
        lifetime, age_add, nonce, ticket_data, max_early_data = _parse_new_session_ticket(data)
        return SessionTicket(
            ticket=ticket_data,
            resumption_secret=self._resumption_secret,
            lifetime=lifetime,
            age_add=age_add,
            nonce=nonce,
            max_early_data=max_early_data,
            timestamp=time.monotonic(),
        )
