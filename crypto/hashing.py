"""
crypto/hashing.py
=================
SHA-256 patient identity protection.

WHY:
  The cloud must never store a patient's real identifier in plaintext.
  We compute SHA-256(user_id) and use only that hash in the cloud layer.

  user_id  →  SHA-256  →  patient_hash  (stored in cloud)
"""

import hashlib


def hash_user_id(user_id: str) -> str:
    """
    Compute SHA-256 hash of a user / patient identifier.

    The returned hexadecimal string is used throughout the system
    wherever the cloud representation must reference a patient WITHOUT
    exposing the real identifier.

    Example
    -------
    >>> hash_user_id("PATIENT_001")
    'a3f2...'   (64-character hex string)
    """
    return hashlib.sha256(user_id.encode("utf-8")).hexdigest()


def verify_user_id(user_id: str, expected_hash: str) -> bool:
    """
    Verify that a given user_id matches a previously stored hash.
    Used for demonstration / integrity checks.
    """
    return hash_user_id(user_id) == expected_hash
