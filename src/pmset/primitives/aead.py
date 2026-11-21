"""Authenticated Encryption with Associated Data (AEAD) for encrypted PMSet buckets.

Uses AES-256-GCM via ``cryptography`` when available, with a self-contained
pure-Python Encrypt-then-MAC (SHA-256-CTR + HMAC-SHA256) fallback so ``pmset``
remains usable even with zero external dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from pmset.primitives.math_utils import hkdf_sha256

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError:  # pragma: no cover
    _AESGCM = None

_SCHEME_AESGCM = 0x01
_SCHEME_FALLBACK_ETM = 0x02


class DecryptionError(ValueError):
    """Raised when AEAD authentication fails (wrong key or tampered ciphertext)."""


def _xor_keystream(enc_key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    blocks = (len(data) + 31) // 32
    offset = 0
    for counter in range(blocks):
        block = hashlib.sha256(enc_key + nonce + counter.to_bytes(4, "big")).digest()
        chunk = data[offset : offset + 32]
        for i, b in enumerate(chunk):
            out[offset + i] = b ^ block[i]
        offset += len(chunk)
    return bytes(out)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt and authenticate ``plaintext`` under a 32-byte ``key``."""
    if len(key) != 32:
        raise ValueError(f"AEAD key must be 32 bytes, got {len(key)}")
    nonce = secrets.token_bytes(12)
    if _AESGCM is not None:
        ct = _AESGCM(key).encrypt(nonce, plaintext, aad)
        return bytes([_SCHEME_AESGCM]) + nonce + ct

    enc_key = hkdf_sha256(key, 32, salt=nonce, info=b"pmset-aead-enc")
    mac_key = hkdf_sha256(key, 32, salt=nonce, info=b"pmset-aead-mac")
    ct = _xor_keystream(enc_key, nonce, plaintext)
    tag = hmac.new(
        mac_key,
        nonce + len(aad).to_bytes(4, "big") + aad + len(ct).to_bytes(4, "big") + ct,
        hashlib.sha256,
    ).digest()
    return bytes([_SCHEME_FALLBACK_ETM]) + nonce + ct + tag


def aead_decrypt(key: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Verify and decrypt an AEAD ciphertext produced by :func:`aead_encrypt`."""
    if len(key) != 32:
        raise ValueError(f"AEAD key must be 32 bytes, got {len(key)}")
    if len(ciphertext) < 1 + 12 + 16:
        raise DecryptionError("Ciphertext too short")
    scheme = ciphertext[0]
    nonce = ciphertext[1:13]
    body = ciphertext[13:]

    if scheme == _SCHEME_AESGCM:
        if _AESGCM is None:
            raise DecryptionError("AES-GCM ciphertext requires the 'cryptography' package")
        try:
            return _AESGCM(key).decrypt(nonce, body, aad)
        except Exception as exc:
            raise DecryptionError("AEAD authentication failed") from exc

    if scheme == _SCHEME_FALLBACK_ETM:
        if len(body) < 32:
            raise DecryptionError("Truncated fallback AEAD ciphertext")
        ct, tag = body[:-32], body[-32:]
        enc_key = hkdf_sha256(key, 32, salt=nonce, info=b"pmset-aead-enc")
        mac_key = hkdf_sha256(key, 32, salt=nonce, info=b"pmset-aead-mac")
        expected = hmac.new(
            mac_key,
            nonce + len(aad).to_bytes(4, "big") + aad + len(ct).to_bytes(4, "big") + ct,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise DecryptionError("AEAD authentication failed")
        return _xor_keystream(enc_key, nonce, ct)

    raise DecryptionError(f"Unknown AEAD scheme byte: 0x{scheme:02x}")
