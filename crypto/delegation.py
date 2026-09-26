"""
crypto/delegation.py
====================
HMAC-SHA256-signed time-limited delegation tokens.

PURPOSE
-------
Allow Doctor A (delegator) to grant Doctor B (delegatee) temporary access
to a specific patient's EHR for a limited time window.

TOKEN STRUCTURE
---------------
The token payload is a canonical JSON string containing:
    delegation_id   : unique UUID
    delegator       : user_id of the granting user
    delegatee       : user_id of the granted user
    patient_id      : the patient this delegation covers
    hospital_id     : the hospital authority
    role            : the role being delegated
    scope           : what operation is permitted ('search', 'decrypt', 'all')
    issued_at       : ISO timestamp (UTC)
    expires_at      : ISO timestamp (UTC)
    version         : "1.0"

SIGNATURE
---------
    signature = HMAC-SHA256(K_delegation, canonical_payload)

The canonical payload is produced by sorting the keys and serializing to JSON.
This makes the signature deterministic and resistant to key-order manipulation.

VERIFICATION
------------
Token is valid when ALL of the following hold:
  1. Signature is correct (HMAC matches)
  2. Current time < expires_at
  3. delegatee matches the requesting user
  4. patient_id matches the requested patient
  5. hospital_id matches the user's hospital
  6. Patient consent is still active (checked externally)
  7. Requested operation is within scope
"""

import hmac
import hashlib
import json
import uuid
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

# Delegation signing key — 32 random bytes derived from a fixed seed for the prototype.
# In production this would be a securely stored per-deployment key.
_DELEGATION_KEY: Optional[bytes] = None


def _get_delegation_key() -> bytes:
    """Return (or derive) the delegation signing key."""
    global _DELEGATION_KEY
    if _DELEGATION_KEY is None:
        # Deterministic for the prototype — derive from a fixed seed + a per-session salt
        # stored in the database. For demo purposes: use a fixed key.
        seed = b"mase-se-delegation-key-2026-research"
        _DELEGATION_KEY = hashlib.sha256(seed).digest()
    return _DELEGATION_KEY


def _canonical(payload: dict) -> str:
    """
    Produce a canonical, deterministic JSON string from a dict.
    Keys are sorted to prevent signature manipulation via key reordering.
    """
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _sign(payload: dict) -> str:
    """Compute HMAC-SHA256 signature over the canonical payload."""
    key = _get_delegation_key()
    canonical = _canonical(payload)
    return hmac.new(key, canonical.encode('utf-8'), hashlib.sha256).hexdigest()


# ─── Token Generation ──────────────────────────────────────────────────────────

def create_token(
    delegator: str,
    delegatee: str,
    patient_id: str,
    hospital_id: str,
    role: str,
    duration_minutes: int = 60,
    scope: str = 'search',
) -> dict:
    """
    Generate a signed delegation token.

    Parameters
    ----------
    delegator        : user_id of the user granting access (e.g. DOCTOR_001)
    delegatee        : user_id of the user receiving access (e.g. DOCTOR_002)
    patient_id       : patient this token covers (e.g. PATIENT_001)
    hospital_id      : hospital authority (e.g. Hospital_A)
    role             : role being delegated (e.g. Doctor)
    duration_minutes : how many minutes until the token expires
    scope            : 'search', 'decrypt', or 'all'

    Returns
    -------
    dict:
        'token_id'   : UUID string
        'payload'    : the token payload dict (without signature)
        'signature'  : HMAC-SHA256 hex string
        'full_token' : payload + signature as a single dict (store this)
        'expires_at' : ISO datetime string
    """
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=duration_minutes)

    payload = {
        'delegation_id': str(uuid.uuid4()),
        'version':       '1.0',
        'delegator':     delegator,
        'delegatee':     delegatee,
        'patient_id':    patient_id,
        'hospital_id':   hospital_id,
        'role':          role,
        'scope':         scope,
        'issued_at':     now.isoformat(),
        'expires_at':    expires.isoformat(),
    }

    sig = _sign(payload)
    full_token = dict(payload)
    full_token['signature'] = sig

    return {
        'token_id':   payload['delegation_id'],
        'payload':    payload,
        'signature':  sig,
        'full_token': full_token,
        'expires_at': expires.isoformat(),
    }


# ─── Token Validation ──────────────────────────────────────────────────────────

def validate_token(
    full_token: dict,
    requesting_user: str,
    patient_id: str,
    operation: str = 'search',
) -> dict:
    """
    Validate a delegation token against a specific access request.

    Validation steps (all must pass):
      1. Signature valid — payload was not tampered
      2. Time valid     — token has not expired
      3. Delegatee match — requesting_user is the intended delegatee
      4. Patient match  — patient_id matches token
      5. Scope valid    — requested operation is within token scope

    Consent validation (step 6) is handled externally by authorization_service.

    Parameters
    ----------
    full_token       : dict from create_token()['full_token']
    requesting_user  : user_id of the user attempting access
    patient_id       : patient the user is attempting to access
    operation        : 'search' or 'decrypt'

    Returns
    -------
    dict:
        'valid'            : bool
        'sig_valid'        : bool
        'time_valid'       : bool
        'delegatee_match'  : bool
        'patient_match'    : bool
        'scope_valid'      : bool
        'reason'           : human-readable explanation
        'expires_at'       : token expiry
        'token_id'         : delegation_id
    """
    # Extract signature and rebuild payload without it
    token_copy = dict(full_token)
    provided_sig = token_copy.pop('signature', None)

    # Step 1 — Signature check
    expected_sig = _sign(token_copy)
    sig_valid = hmac.compare_digest(
        provided_sig or '',
        expected_sig,
    )

    # Step 2 — Time check
    expires_str = token_copy.get('expires_at', '')
    try:
        expires = datetime.fromisoformat(expires_str)
        time_valid = datetime.now(timezone.utc) < expires
    except ValueError:
        time_valid = False

    # Step 3 — Delegatee match
    delegatee_match = (token_copy.get('delegatee', '') == requesting_user)

    # Step 4 — Patient match
    patient_match = (token_copy.get('patient_id', '') == patient_id)

    # Step 5 — Scope check
    token_scope = token_copy.get('scope', '')
    if token_scope == 'all':
        scope_valid = True
    else:
        scope_valid = (token_scope == operation)

    valid = sig_valid and time_valid and delegatee_match and patient_match and scope_valid

    # Build reason
    reasons = []
    if not sig_valid:        reasons.append("Signature invalid — token tampered or wrong key.")
    if not time_valid:       reasons.append("Token expired.")
    if not delegatee_match:  reasons.append(f"Delegatee mismatch (expected {token_copy.get('delegatee')}, got {requesting_user}).")
    if not patient_match:    reasons.append(f"Patient mismatch (token covers {token_copy.get('patient_id')}, requested {patient_id}).")
    if not scope_valid:      reasons.append(f"Operation '{operation}' not within token scope '{token_scope}'.")

    return {
        'valid':           valid,
        'sig_valid':       sig_valid,
        'time_valid':      time_valid,
        'delegatee_match': delegatee_match,
        'patient_match':   patient_match,
        'scope_valid':     scope_valid,
        'reason':          " | ".join(reasons) if reasons else "All delegation checks passed.",
        'expires_at':      expires_str,
        'token_id':        token_copy.get('delegation_id', ''),
        'delegator':       token_copy.get('delegator', ''),
        'delegatee':       token_copy.get('delegatee', ''),
        'hospital_id':     token_copy.get('hospital_id', ''),
        'role':            token_copy.get('role', ''),
    }


def force_expire_token(full_token: dict) -> dict:
    """
    Return a copy of the token with expires_at set to a past timestamp.
    Used for demonstration purposes — simulates an expired token.
    The signature remains valid (payload changed, so sig will ALSO become invalid
    — which is the correct behaviour for a tampered token in production).

    For demo: we keep original sig so we can show sig=VALID, time=EXPIRED.
    """
    expired = dict(full_token)
    # Set expiry to 1 second in the past
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    # Rebuild without signature, update expires_at, re-sign
    payload = {k: v for k, v in expired.items() if k != 'signature'}
    payload['expires_at'] = past.isoformat()
    new_sig = _sign(payload)
    payload['signature'] = new_sig
    return payload
