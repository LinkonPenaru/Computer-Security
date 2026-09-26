"""
crypto/ehr_encryption.py
========================
AES-256-GCM symmetric authenticated encryption for EHR records.

IMPLEMENTED MECHANISM (60% prototype):
  AES-256-GCM with a fresh random 16-byte nonce per encryption.
  GCM mode provides both confidentiality AND authenticity (built-in MAC tag).

FUTURE EXTENSION (40%):
  The AES key will itself be protected by Multi-Authority CP-ABE.
  Currently the key is managed per-hospital and stored in the database.

IMPORTANT:
  - The nonce MUST NOT be reused with the same key.
  - A new nonce is generated for every encrypt_ehr() call.
  - The nonce and GCM tag are stored alongside the ciphertext.
  - Decryption will FAIL (raise ValueError) if the tag does not match,
    detecting any tampering or wrong key.
"""

import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_key() -> bytes:
    """
    Generate a cryptographically secure random 256-bit (32-byte) AES key.

    Returns
    -------
    bytes : 32 random bytes suitable for AES-256.
    """
    return get_random_bytes(32)


def key_to_b64(key: bytes) -> str:
    """Encode a raw key to a base64 string for database storage."""
    return base64.b64encode(key).decode("utf-8")


def key_from_b64(b64_str: str) -> bytes:
    """Decode a base64 string back to raw key bytes."""
    return base64.b64decode(b64_str)


def encrypt_ehr(plaintext: str, key: bytes) -> dict:
    """
    Encrypt an EHR record using AES-256-GCM.

    Parameters
    ----------
    plaintext : str
        The raw EHR content (diagnoses, dates, etc.) to protect.
    key : bytes
        A 32-byte AES-256 key for this hospital.

    Returns
    -------
    dict with keys:
        'ciphertext' : base64-encoded ciphertext
        'nonce'      : base64-encoded 16-byte nonce (MUST be stored)
        'tag'        : base64-encoded 16-byte GCM authentication tag

    Notes
    -----
    A fresh nonce is generated for every call.
    The nonce and tag are required for decryption and integrity verification.
    """
    nonce = get_random_bytes(16)          # fresh nonce every call
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce":      base64.b64encode(nonce).decode("utf-8"),
        "tag":        base64.b64encode(tag).decode("utf-8"),
    }


def decrypt_ehr(ciphertext_b64: str, nonce_b64: str, tag_b64: str, key: bytes) -> str:
    """
    Decrypt an AES-256-GCM encrypted EHR record.

    Parameters
    ----------
    ciphertext_b64 : str  — base64-encoded ciphertext from encrypt_ehr()
    nonce_b64      : str  — base64-encoded nonce from encrypt_ehr()
    tag_b64        : str  — base64-encoded GCM tag from encrypt_ehr()
    key            : bytes — the 32-byte AES key for this hospital

    Returns
    -------
    str : decrypted plaintext EHR content

    Raises
    ------
    ValueError
        If the GCM authentication tag does not match.
        This means either the key is wrong OR the ciphertext was tampered.
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce      = base64.b64decode(nonce_b64)
    tag        = base64.b64decode(tag_b64)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext_bytes.decode("utf-8")
    except (ValueError, KeyError) as exc:
        raise ValueError(
            "EHR decryption FAILED: authentication tag mismatch. "
            "The key may be incorrect or the ciphertext has been tampered with."
        ) from exc
