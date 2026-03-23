"""QUIC packet protection — key derivation, AEAD, header protection (RFC 9001)."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zoomies.crypto._hkdf import hkdf_expand_label, hkdf_extract
from zoomies.packet.header import decode_packet_number
from zoomies.primitives.types import QUIC_VERSION_1

# RFC 9001 5.2: Initial salt for QUIC v1
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
SAMPLE_SIZE = 16


def derive_key_iv_hp(
    *,
    secret: bytes,
    version: int = QUIC_VERSION_1,
) -> tuple[bytes, bytes, bytes]:
    """Derive key, IV, and header protection key (RFC 9001 A.1)."""
    key = hkdf_expand_label(hashes.SHA256, secret, b"quic key", b"", 16)
    iv = hkdf_expand_label(hashes.SHA256, secret, b"quic iv", b"", 12)
    hp = hkdf_expand_label(hashes.SHA256, secret, b"quic hp", b"", 16)
    return key, iv, hp


def _quic_nonce(iv: bytes, packet_number: int) -> bytes:
    """QUIC nonce (RFC 9001 5.3): IV XOR with 4 zero bytes + 8-byte PN."""
    iv_int = int.from_bytes(iv, "big")
    return (iv_int ^ packet_number).to_bytes(12, "big")


def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-ECB encrypt (for header protection)."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


class CryptoContext:
    """Single-direction crypto context (AEAD + header protection)."""

    def __init__(self) -> None:
        self._key: bytes | None = None
        self._iv: bytes | None = None
        self._hp: bytes | None = None
        self._aead: AESGCM | None = None
        self._hp_cipher: Cipher | None = None

    def setup(self, *, secret: bytes, version: int = QUIC_VERSION_1) -> None:
        """Set up from secret."""
        key, iv, hp = derive_key_iv_hp(secret=secret, version=version)
        self._key = key
        self._iv = iv
        self._hp = hp
        self._aead = AESGCM(key)
        self._hp_cipher = Cipher(algorithms.AES(hp), modes.ECB())

    def _encrypt_payload(self, plain: bytes, header: bytes, pn: int) -> bytes:
        """AEAD encrypt (RFC 9001 5.3)."""
        if self._aead is None or self._iv is None:
            raise RuntimeError("Crypto not initialized")
        nonce = _quic_nonce(self._iv, pn)
        return self._aead.encrypt(nonce, plain, header)

    def _decrypt_payload(self, ciphertext: bytes, header: bytes, pn: int) -> bytes:
        """AEAD decrypt."""
        if self._aead is None or self._iv is None:
            raise RuntimeError("Crypto not initialized")
        nonce = _quic_nonce(self._iv, pn)
        return self._aead.decrypt(nonce, ciphertext, header)

    def _hp_encrypt(self, data: bytes) -> bytes:
        """AES-ECB encrypt for header protection (cached cipher)."""
        if self._hp_cipher is None:
            raise RuntimeError("Crypto not initialized")
        encryptor = self._hp_cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def _apply_header_protection(
        self, header: bytes, payload: bytes, pn_len: int
    ) -> tuple[bytes, bytes]:
        """Apply header protection; returns (masked_header, masked_payload).

        RFC 9001 5.4.2: sample is taken 4 bytes after PN start.
        """
        if self._hp is None:
            raise RuntimeError("Crypto not initialized")
        sample_offset = 4
        sample = payload[sample_offset : sample_offset + SAMPLE_SIZE]
        mask = self._hp_encrypt(sample)
        mask_first = mask[0] & (0x0F if (header[0] & 0x80) else 0x1F)
        masked_header = bytes([header[0] ^ mask_first]) + header[1:]
        masked_start = bytes(payload[i] ^ mask[1 + i] for i in range(pn_len))
        return masked_header, masked_start + payload[pn_len:]

    def _remove_header_protection(
        self, packet: bytes, encrypted_offset: int, pn_len: int
    ) -> tuple[bytes, bytes]:
        """Remove header protection; return (plain_header, ciphertext).

        RFC 9001 5.4.2: sample is taken 4 bytes after PN start (assume 4-byte PN).
        """
        if self._hp is None:
            raise RuntimeError("Crypto not initialized")
        sample_offset = encrypted_offset + 4
        sample = packet[sample_offset : sample_offset + SAMPLE_SIZE]
        mask = self._hp_encrypt(sample)
        mask_first = mask[0] & (0x0F if (packet[0] & 0x80) else 0x1F)
        plain_header = bytes([packet[0] ^ mask_first]) + packet[1:encrypted_offset]
        unmasked_start = bytes(packet[encrypted_offset + i] ^ mask[1 + i] for i in range(pn_len))
        ciphertext = unmasked_start + packet[encrypted_offset + pn_len :]
        return plain_header, ciphertext


class CryptoPair:
    """Bidirectional crypto — send and receive contexts."""

    def __init__(self) -> None:
        self._recv = CryptoContext()
        self._send = CryptoContext()

    def setup_initial(
        self,
        cid: bytes,
        is_client: bool,
        version: int = QUIC_VERSION_1,
    ) -> None:
        """Set up Initial keys from connection ID (RFC 9001 5.2)."""
        initial_secret = hkdf_extract(hashes.SHA256, INITIAL_SALT_V1, cid)
        if is_client:
            recv_label, send_label = b"server in", b"client in"
        else:
            recv_label, send_label = b"client in", b"server in"
        recv_secret = hkdf_expand_label(
            hashes.SHA256,
            initial_secret,
            recv_label,
            b"",
            hashes.SHA256.digest_size,
        )
        send_secret = hkdf_expand_label(
            hashes.SHA256,
            initial_secret,
            send_label,
            b"",
            hashes.SHA256.digest_size,
        )
        self._recv.setup(secret=recv_secret, version=version)
        self._send.setup(secret=send_secret, version=version)

    def setup_handshake(
        self,
        handshake_secret: bytes,
        is_client: bool,
        version: int = QUIC_VERSION_1,
    ) -> None:
        """Set up Handshake keys from TLS handshake_secret (RFC 9001 A.2)."""
        if is_client:
            recv_label, send_label = b"s hs", b"c hs"
        else:
            recv_label, send_label = b"c hs", b"s hs"
        recv_secret = hkdf_expand_label(
            hashes.SHA256,
            handshake_secret,
            recv_label,
            b"",
            hashes.SHA256.digest_size,
        )
        send_secret = hkdf_expand_label(
            hashes.SHA256,
            handshake_secret,
            send_label,
            b"",
            hashes.SHA256.digest_size,
        )
        self._recv.setup(secret=recv_secret, version=version)
        self._send.setup(secret=send_secret, version=version)

    def setup_1rtt(
        self,
        traffic_secret: bytes,
        is_client: bool,
        version: int = QUIC_VERSION_1,
    ) -> None:
        """Set up 1-RTT keys from TLS application traffic secret (RFC 9001 A.3)."""
        if is_client:
            recv_label, send_label = b"s ap", b"c ap"
        else:
            recv_label, send_label = b"c ap", b"s ap"
        recv_secret = hkdf_expand_label(
            hashes.SHA256,
            traffic_secret,
            recv_label,
            b"",
            hashes.SHA256.digest_size,
        )
        send_secret = hkdf_expand_label(
            hashes.SHA256,
            traffic_secret,
            send_label,
            b"",
            hashes.SHA256.digest_size,
        )
        self._recv.setup(secret=recv_secret, version=version)
        self._send.setup(secret=send_secret, version=version)

    def encrypt_packet(
        self,
        plain_header: bytes,
        plain_payload: bytes,
        packet_number: int,
    ) -> bytes:
        """Encrypt packet (payload protection then header protection)."""
        pn_len = 4
        pn_bytes = packet_number.to_bytes(pn_len, "big")
        plain = pn_bytes + plain_payload
        ciphertext = self._send._encrypt_payload(plain, plain_header, packet_number)
        protected_header, protected_payload = self._send._apply_header_protection(
            plain_header, ciphertext, pn_len
        )
        return protected_header + protected_payload

    def decrypt_packet(
        self,
        packet: bytes,
        encrypted_offset: int,
        expected_packet_number: int,
    ) -> tuple[bytes, bytes, int]:
        """Decrypt packet; returns (plain_header, plain_payload, packet_number)."""
        pn_len = 4
        plain_header, ciphertext = self._recv._remove_header_protection(
            packet, encrypted_offset, pn_len
        )
        plain = self._recv._decrypt_payload(ciphertext, plain_header, expected_packet_number)
        pn_bytes = plain[:pn_len]
        pn = int.from_bytes(pn_bytes, "big")
        pn = decode_packet_number(pn, pn_len * 8, expected_packet_number)
        plain_payload = plain[pn_len:]
        return plain_header, plain_payload, pn
