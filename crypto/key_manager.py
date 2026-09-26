"""
crypto/key_manager.py
=====================
Per-hospital key management for the 60% prototype.

IMPLEMENTED MECHANISM:
  Each hospital has two 256-bit keys:
    - ehr_key    : AES-256-GCM key for encrypting EHR records
    - search_key : HMAC-SHA256 key for generating search tokens

  These are generated once (at system setup) and stored in the database.
  They are loaded into memory at application startup.

FUTURE EXTENSION (40%):
  Replace with Shamir (2-of-3) MPC secret sharing.
  Each hospital issues a KEY SHARE rather than a full key.
  A doctor needs 2-of-3 shares to reconstruct a decryption key.
  No single hospital ever holds the complete user key.

  Placeholder interfaces for the MPC layer are included below.
"""

import base64
from Crypto.Random import get_random_bytes
from typing import Dict, Optional


# In-memory key store — populated at startup from the database
_ehr_keys:    Dict[str, bytes] = {}
_search_keys: Dict[str, bytes] = {}

HOSPITALS = ["Hospital_A", "Hospital_B", "Hospital_C"]


# ─── Initialisation ────────────────────────────────────────────────────────────

def initialize_keys(stored_keys: Optional[dict] = None) -> dict:
    """
    Load or generate hospital keys.

    If stored_keys is provided (dict loaded from DB), decode and cache them.
    Otherwise, generate new random keys and return them for DB storage.

    Parameters
    ----------
    stored_keys : dict or None
        {hospital_id: {'ehr_key': '<base64>', 'search_key': '<base64>'}}

    Returns
    -------
    dict : same structure — ready to save to DB if newly generated.
    """
    global _ehr_keys, _search_keys

    if stored_keys:
        for hosp in HOSPITALS:
            if hosp in stored_keys:
                _ehr_keys[hosp]    = base64.b64decode(stored_keys[hosp]["ehr_key"])
                _search_keys[hosp] = base64.b64decode(stored_keys[hosp]["search_key"])
        return stored_keys

    # Generate fresh keys
    result = {}
    for hosp in HOSPITALS:
        ek = get_random_bytes(32)
        sk = get_random_bytes(32)
        _ehr_keys[hosp]    = ek
        _search_keys[hosp] = sk
        result[hosp] = {
            "ehr_key":    base64.b64encode(ek).decode(),
            "search_key": base64.b64encode(sk).decode(),
        }
    return result


def keys_initialized() -> bool:
    """Return True if keys have been loaded for all hospitals."""
    return all(h in _ehr_keys for h in HOSPITALS)


# ─── Key Retrieval ─────────────────────────────────────────────────────────────

def get_ehr_key(hospital_id: str) -> bytes:
    """
    Retrieve the AES-256 EHR encryption key for a hospital.
    Raises KeyError if the hospital is unknown or keys not initialised.
    """
    if hospital_id not in _ehr_keys:
        raise KeyError(
            f"No EHR key for '{hospital_id}'. "
            "Ensure initialize_keys() was called at startup."
        )
    return _ehr_keys[hospital_id]


def get_search_key(hospital_id: str) -> bytes:
    """
    Retrieve the HMAC-SHA256 search key for a hospital.
    Raises KeyError if the hospital is unknown or keys not initialised.
    """
    if hospital_id not in _search_keys:
        raise KeyError(
            f"No search key for '{hospital_id}'. "
            "Ensure initialize_keys() was called at startup."
        )
    return _search_keys[hospital_id]


# ─── Future MPC Placeholders ───────────────────────────────────────────────────

def mpc_issue_key_share(hospital_id: str, user_id: str) -> str:
    """
    FUTURE EXTENSION (40%):
    Each hospital uses Shamir Secret Sharing to issue a KEY SHARE
    to the requesting user.  The user needs 2-of-3 shares to reconstruct
    the full decryption key.

    Current status: stub / placeholder only.
    """
    return (
        f"[MPC PLACEHOLDER] Hospital '{hospital_id}' would issue "
        f"a Shamir share to user '{user_id}' here. "
        "Implement Shamir (2,3) in the 40% extension."
    )


def mpc_reconstruct_key(shares: list) -> str:
    """
    FUTURE EXTENSION (40%):
    Reconstruct the full key from 2-of-3 Shamir shares using
    Lagrange interpolation over GF(2^127 - 1).

    Current status: stub / placeholder only.
    """
    return (
        "[MPC PLACEHOLDER] Key reconstruction from Shamir shares "
        "will be implemented in the 40% extension."
    )
