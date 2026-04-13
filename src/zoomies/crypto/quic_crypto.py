"""QUIC packet protection — key derivation, AEAD, header protection (RFC 9001)."""

from cryptography.exceptions import InvalidTag
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
        self._secret: bytes | None = None

    def setup(self, *, secret: bytes, version: int = QUIC_VERSION_1) -> None:
        """Set up from secret."""
        self._secret = secret
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
        self._key_phase: int = 0
        self._old_recv: CryptoContext | None = None  # previous recv keys for reordered packets

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

    def setup_0rtt(
        self,
        early_secret: bytes,
        client_hello_hash: bytes,
        is_client: bool,
        version: int = QUIC_VERSION_1,
    ) -> None:
        """Set up 0-RTT keys from early_secret and ClientHello transcript hash.

        0-RTT is unidirectional: client sends, server receives.
        Derives client_early_traffic_secret per RFC 8446 §7.1,
        then QUIC AEAD keys per RFC 9001 §5.
        """
        client_early_traffic_secret = hkdf_expand_label(
            hashes.SHA256,
            early_secret,
            b"c e traffic",
            client_hello_hash,
            hashes.SHA256.digest_size,
        )
        if is_client:
            self._send.setup(secret=client_early_traffic_secret, version=version)
        else:
            self._recv.setup(secret=client_early_traffic_secret, version=version)

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

    @property
    def key_phase(self) -> int:
        """Current key phase bit (0 or 1)."""
        return self._key_phase

    def update_keys(self) -> None:
        """Perform key update (RFC 9001 §6).

        Derives new secrets using HKDF-Expand-Label with "quic ku" label,
        then sets up new AEAD keys. Flips the key phase bit.
        Retains old receive keys for reordered packets (RFC 9001 §6.5).
        """
        if self._recv._secret is None or self._send._secret is None:
            raise RuntimeError("Cannot update keys: 1-RTT keys not set up")
        new_recv_secret = hkdf_expand_label(
            hashes.SHA256,
            self._recv._secret,
            b"quic ku",
            b"",
            hashes.SHA256.digest_size,
        )
        new_send_secret = hkdf_expand_label(
            hashes.SHA256,
            self._send._secret,
            b"quic ku",
            b"",
            hashes.SHA256.digest_size,
        )
        # Retain old recv keys for reordered packets
        self._old_recv = self._recv
        self._recv = CryptoContext()
        self._recv.setup(secret=new_recv_secret)
        self._send.setup(secret=new_send_secret)
        self._key_phase ^= 1

    def discard_old_keys(self) -> None:
        """Discard old receive keys (call after one PTO)."""
        self._old_recv = None

    def decrypt_packet_with_phase(
        self,
        packet: bytes,
        encrypted_offset: int,
        expected_packet_number: int,
    ) -> tuple[bytes, bytes, int, int]:
        """Decrypt packet with key phase detection (RFC 9001 §6).

        Returns (plain_header, plain_payload, packet_number, key_phase_bit).
        On InvalidTag with current keys, tries next-generation keys if key phase
        differs. On success with next-gen keys, commits the key update.
        """
        pn_len = 4
        # Try current keys first
        try:
            plain_header, ciphertext = self._recv._remove_header_protection(
                packet, encrypted_offset, pn_len
            )
            incoming_phase = (plain_header[0] >> 2) & 1
            plain = self._recv._decrypt_payload(
                ciphertext, plain_header, expected_packet_number
            )
            pn_bytes = plain[:pn_len]
            pn = int.from_bytes(pn_bytes, "big")
            pn = decode_packet_number(pn, pn_len * 8, expected_packet_number)
            plain_payload = plain[pn_len:]
            return plain_header, plain_payload, pn, incoming_phase
        except InvalidTag:
            # Header protection was already removed, check if key phase differs
            incoming_phase = (plain_header[0] >> 2) & 1
            if incoming_phase == self._key_phase:
                # Same phase — genuine decryption failure, try old keys for reorder
                if self._old_recv is not None:
                    try:
                        old_plain = self._old_recv._decrypt_payload(
                            ciphertext, plain_header, expected_packet_number
                        )
                        pn_bytes = old_plain[:pn_len]
                        pn = int.from_bytes(pn_bytes, "big")
                        pn = decode_packet_number(pn, pn_len * 8, expected_packet_number)
                        plain_payload = old_plain[pn_len:]
                        return plain_header, plain_payload, pn, incoming_phase
                    except InvalidTag:
                        pass
                raise
            # Different phase — peer initiated key update, try next-gen keys
            next_recv_secret = hkdf_expand_label(
                hashes.SHA256,
                self._recv._secret,
                b"quic ku",
                b"",
                hashes.SHA256.digest_size,
            )
            next_recv = CryptoContext()
            next_recv.setup(secret=next_recv_secret)
            try:
                plain = next_recv._decrypt_payload(
                    ciphertext, plain_header, expected_packet_number
                )
            except InvalidTag:
                raise  # Neither current nor next-gen keys work
            # Success — commit the key update
            pn_bytes = plain[:pn_len]
            pn = int.from_bytes(pn_bytes, "big")
            pn = decode_packet_number(pn, pn_len * 8, expected_packet_number)
            plain_payload = plain[pn_len:]
            self.update_keys()
            return plain_header, plain_payload, pn, incoming_phase

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
