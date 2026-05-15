"""
crypto_utils.py — Cryptographic Utilities
==========================================
Provides AES, RSA, SHA-256, DES, and S-DES primitives for the
secure-communication / MITM demonstration project.

All public symbols are importable from a single namespace:
    from crypto_utils import generate_rsa_keypair, aes_encrypt, ...
"""

import os
import hashlib
import struct
import logging

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# RSA
# ─────────────────────────────────────────────────────────────────────────────

def generate_rsa_keypair(bits: int = 2048) -> tuple[bytes, bytes]:
    """
    Generate an RSA key-pair.

    Returns
    -------
    (private_pem, public_pem) — both as PEM-encoded bytes.
    """
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()


def rsa_encrypt(public_pem: bytes, data: bytes) -> bytes:
    """Encrypt *data* with an RSA public key (OAEP / SHA-256)."""
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(data)


def rsa_decrypt(private_pem: bytes, ciphertext: bytes) -> bytes:
    """Decrypt RSA ciphertext with a private key."""
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(ciphertext)


# ─────────────────────────────────────────────────────────────────────────────
# AES  (CBC mode, PKCS#7 padding, random IV prepended to ciphertext)
# ─────────────────────────────────────────────────────────────────────────────

AES_KEY_SIZE = 32   # 256-bit
AES_BLOCK    = 16


def generate_aes_key() -> bytes:
    """Return a fresh 256-bit AES key."""
    return get_random_bytes(AES_KEY_SIZE)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-CBC encrypt *plaintext*.

    Returns
    -------
    iv (16 bytes) + ciphertext  (both concatenated).
    """
    iv     = get_random_bytes(AES_BLOCK)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, AES_BLOCK))


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    """
    AES-CBC decrypt.  *blob* = iv (16 bytes) + ciphertext.
    Raises ValueError on bad padding / wrong key.
    """
    iv, ct = blob[:AES_BLOCK], blob[AES_BLOCK:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES_BLOCK)


# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 integrity
# ─────────────────────────────────────────────────────────────────────────────

def sha256_digest(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def verify_integrity(data: bytes, expected_digest: bytes) -> bool:
    """Return True if SHA-256(data) == expected_digest."""
    return hashlib.compare_digest(sha256_digest(data), expected_digest)


# ─────────────────────────────────────────────────────────────────────────────
# Hybrid encryption helpers  (used by sender / receiver)
# ─────────────────────────────────────────────────────────────────────────────

def hybrid_encrypt(
    receiver_public_pem: bytes,
    plaintext: bytes,
    msg_type: str = "text",
) -> dict:
    """
    Encrypt *plaintext* with hybrid RSA+AES.

    Returns a dict with keys:
        encrypted_key   — RSA-encrypted AES key  (bytes)
        ciphertext      — AES-encrypted payload   (bytes)
        digest          — SHA-256 of plaintext     (bytes)
        msg_type        — 'text' or 'audio'
    """
    aes_key       = generate_aes_key()
    ciphertext    = aes_encrypt(aes_key, plaintext)
    encrypted_key = rsa_encrypt(receiver_public_pem, aes_key)
    digest        = sha256_digest(plaintext)

    logger.debug("hybrid_encrypt: type=%s plaintext_len=%d", msg_type, len(plaintext))
    return {
        "encrypted_key": encrypted_key,
        "ciphertext":    ciphertext,
        "digest":        digest,
        "msg_type":      msg_type,
    }


def hybrid_decrypt(private_pem: bytes, packet: dict) -> bytes:
    """
    Decrypt a packet produced by *hybrid_encrypt*.

    Raises
    ------
    ValueError  if integrity check fails.
    """
    aes_key   = rsa_decrypt(private_pem, packet["encrypted_key"])
    plaintext = aes_decrypt(aes_key, packet["ciphertext"])

    if not verify_integrity(plaintext, packet["digest"]):
        raise ValueError("Integrity check FAILED — message may have been tampered with.")

    logger.debug("hybrid_decrypt: type=%s plaintext_len=%d", packet.get("msg_type"), len(plaintext))
    return plaintext


# ─────────────────────────────────────────────────────────────────────────────
# DES (pycryptodome wrapper — for comparison / demo only)
# ─────────────────────────────────────────────────────────────────────────────

DES_KEY_SIZE = 8   # 64-bit (56 effective)


def des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """DES-CBC encrypt (educational / comparison only)."""
    if len(key) != DES_KEY_SIZE:
        raise ValueError(f"DES key must be {DES_KEY_SIZE} bytes.")
    iv     = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, 8))


def des_decrypt(key: bytes, blob: bytes) -> bytes:
    """DES-CBC decrypt (educational / comparison only)."""
    if len(key) != DES_KEY_SIZE:
        raise ValueError(f"DES key must be {DES_KEY_SIZE} bytes.")
    iv, ct = blob[:8], blob[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 8)


# ─────────────────────────────────────────────────────────────────────────────
# S-DES  (Simplified DES — pure Python, textbook implementation)
# ─────────────────────────────────────────────────────────────────────────────
# This is a toy 10-bit key / 8-bit block cipher for classroom demonstrations.
# It does NOT provide any real security.

class SDES:
    """
    Simplified DES (S-DES) as described in Stallings' *Cryptography and
    Network Security* textbook (10-bit key, 8-bit block).

    Usage
    -----
    sdes = SDES(key_10bit_int)
    ct   = sdes.encrypt_byte(pt_byte)
    pt   = sdes.decrypt_byte(ct_byte)
    """

    # ── permutation tables ────────────────────────────────────────────────
    _P10  = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
    _P8   = (6, 3, 7, 4, 8, 5, 10, 9)
    _IP   = (2, 6, 3, 1, 4, 8, 5, 7)
    _IP_I = (4, 1, 3, 5, 7, 2, 8, 6)
    _EP   = (4, 1, 2, 3, 2, 3, 4, 1)
    _P4   = (2, 4, 3, 1)

    _S0 = [[1, 0, 3, 2],
           [3, 2, 1, 0],
           [0, 2, 1, 3],
           [3, 1, 3, 2]]

    _S1 = [[0, 1, 2, 3],
           [2, 0, 1, 3],
           [3, 0, 1, 0],
           [2, 1, 0, 3]]

    # ── helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _perm(bits: list[int], table: tuple) -> list[int]:
        return [bits[t - 1] for t in table]

    @staticmethod
    def _int_to_bits(n: int, length: int) -> list[int]:
        return [(n >> (length - 1 - i)) & 1 for i in range(length)]

    @staticmethod
    def _bits_to_int(bits: list[int]) -> int:
        result = 0
        for b in bits:
            result = (result << 1) | b
        return result

    @staticmethod
    def _left_shift(bits: list[int], n: int) -> list[int]:
        return bits[n:] + bits[:n]

    # ── key schedule ──────────────────────────────────────────────────────
    def _generate_subkeys(self, key_int: int):
        bits = self._int_to_bits(key_int, 10)
        p10  = self._perm(bits, self._P10)
        left, right = p10[:5], p10[5:]

        left1, right1 = self._left_shift(left, 1), self._left_shift(right, 1)
        self._k1 = self._perm(left1 + right1, self._P8)

        left2, right2 = self._left_shift(left1, 2), self._left_shift(right1, 2)
        self._k2 = self._perm(left2 + right2, self._P8)

    def __init__(self, key_10bit: int):
        if not (0 <= key_10bit < 1024):
            raise ValueError("S-DES key must be a 10-bit integer (0–1023).")
        self._generate_subkeys(key_10bit)

    # ── S-box lookup ──────────────────────────────────────────────────────
    def _sbox(self, bits4: list[int], sbox: list) -> list[int]:
        row = (bits4[0] << 1) | bits4[3]
        col = (bits4[1] << 1) | bits4[2]
        return self._int_to_bits(sbox[row][col], 2)

    # ── F function ────────────────────────────────────────────────────────
    def _f(self, right4: list[int], subkey: list[int]) -> list[int]:
        ep  = self._perm(right4, self._EP)
        xor = [a ^ b for a, b in zip(ep, subkey)]
        s0  = self._sbox(xor[:4], self._S0)
        s1  = self._sbox(xor[4:], self._S1)
        return self._perm(s0 + s1, self._P4)

    # ── Feistel round ─────────────────────────────────────────────────────
    def _fk(self, bits8: list[int], subkey: list[int]) -> list[int]:
        left, right = bits8[:4], bits8[4:]
        f_out = self._f(right, subkey)
        return [l ^ f for l, f in zip(left, f_out)] + right

    # ── encrypt / decrypt ─────────────────────────────────────────────────
    def encrypt_byte(self, plaintext_byte: int) -> int:
        bits  = self._int_to_bits(plaintext_byte, 8)
        ip    = self._perm(bits, self._IP)
        r1    = self._fk(ip, self._k1)
        sw    = r1[4:] + r1[:4]              # SW (swap)
        r2    = self._fk(sw, self._k2)
        ip_i  = self._perm(r2, self._IP_I)
        return self._bits_to_int(ip_i)

    def decrypt_byte(self, ciphertext_byte: int) -> int:
        bits  = self._int_to_bits(ciphertext_byte, 8)
        ip    = self._perm(bits, self._IP)
        r1    = self._fk(ip, self._k2)      # note: k2 first
        sw    = r1[4:] + r1[:4]
        r2    = self._fk(sw, self._k1)
        ip_i  = self._perm(r2, self._IP_I)
        return self._bits_to_int(ip_i)

    def encrypt_bytes(self, data: bytes) -> bytes:
        return bytes(self.encrypt_byte(b) for b in data)

    def decrypt_bytes(self, data: bytes) -> bytes:
        return bytes(self.decrypt_byte(b) for b in data)
