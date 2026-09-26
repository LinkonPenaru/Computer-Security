"""
crypto/policy_hiding.py
=======================
Prototype policy-hiding mechanism — protected policy attribute representation.

IMPORTANT DISCLAIMER
--------------------
This is a PROTOTYPE policy-hiding mechanism, NOT a formal hidden-policy CP-ABE scheme.

In a formal hidden-policy CP-ABE construction (e.g., as used in research papers),
access policies are encoded into ciphertext using pairing-based cryptography such
that the cloud can test a user's attribute key against the policy without learning
the policy's plaintext content. Implementing a full pairing-based scheme is beyond
the scope of this prototype.

WHAT THIS MODULE IMPLEMENTS
----------------------------
A practical, demonstrable prototype-level policy protection where:

  - Policy attributes (hospital, role, consent status) are represented as
    HMAC-SHA256 commitments rather than plaintext strings.
  - The cloud-side representation stores these commitments, not "Hospital_A" or "Doctor".
  - The authorization layer computes the same commitments from a user's attributes
    and checks whether they match the stored protected policy.
  - This prevents a cloud operator who inspects the database from directly reading
    the authorization structure from plaintext field values.

WHAT THIS IS NOT
----------------
  - Not cryptographically equivalent to pairing-based hidden-policy ABE.
  - Not information-theoretically hiding (the commitment key K_policy is held
    by the application, not distributed).
  - Suitable for demonstrating the concept in an academic prototype context.
"""

import hmac
import hashlib
import json
import os
import base64
from typing import Optional

# Policy protection key — derived deterministically for the prototype.
_POLICY_KEY: Optional[bytes] = None


def _get_policy_key() -> bytes:
    """Return (or derive) the policy commitment key."""
    global _POLICY_KEY
    if _POLICY_KEY is None:
        seed = b"mase-se-policy-hiding-key-2026-research"
        _POLICY_KEY = hashlib.sha256(seed).digest()
    return _POLICY_KEY


def _commit(attribute: str) -> str:
    """
    Compute HMAC-SHA256 commitment for a single attribute value.

    The cloud stores this commitment. It cannot reverse it to learn
    the plaintext attribute without knowledge of K_policy.

    Parameters
    ----------
    attribute : str — e.g. 'Hospital_A', 'Doctor', 'ACTIVE'

    Returns
    -------
    str : 64-char hex commitment
    """
    key = _get_policy_key()
    return hmac.new(
        key,
        attribute.strip().upper().encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


# ─── Public API ───────────────────────────────────────────────────────────────

def build_protected_policy(patient_id: str, hospital_id: str, role: str, status: str) -> dict:
    """
    Build a protected (cloud-side) policy representation for one consent entry.

    The returned dict is what would be stored/shown in cloud storage.
    It contains HMAC commitments rather than plaintext attribute values.

    Parameters
    ----------
    patient_id  : str — e.g. 'PATIENT_001'
    hospital_id : str — e.g. 'Hospital_A'
    role        : str — e.g. 'Doctor'
    status      : str — 'ACTIVE' or 'REVOKED'

    Returns
    -------
    dict:
        'policy_id'                 : deterministic identifier
        'protected_hospital'        : HMAC(K, hospital_id)
        'protected_role'            : HMAC(K, role)
        'protected_status'          : HMAC(K, status)
        'protected_patient'         : HMAC(K, patient_id)
        'logical_view'              : plaintext representation (app-side only, NOT stored in cloud)
        'cloud_view'                : what the cloud sees (commitments only)
    """
    protected_hospital = _commit(hospital_id)
    protected_role     = _commit(role)
    protected_status   = _commit(status)
    protected_patient  = _commit(patient_id)

    # Policy ID: HMAC over all four commitments — binds them together
    policy_id = hmac.new(
        _get_policy_key(),
        (protected_hospital + protected_role + protected_patient).encode(),
        hashlib.sha256,
    ).hexdigest()[:32]

    return {
        'policy_id':           policy_id,
        'protected_hospital':  protected_hospital,
        'protected_role':      protected_role,
        'protected_status':    protected_status,
        'protected_patient':   protected_patient,

        # Logical view — shown only in the "application layer" panel (not cloud)
        'logical_view': {
            'hospital': hospital_id,
            'role':     role,
            'status':   status,
            'patient':  patient_id,
        },
        # Cloud view — what actually goes to storage
        'cloud_view': {
            'policy_id':          policy_id,
            'protected_hospital': protected_hospital[:24] + '...',
            'protected_role':     protected_role[:24]     + '...',
            'protected_status':   protected_status[:24]   + '...',
            'protected_patient':  protected_patient[:24]  + '...',
        },
    }


def match_policy(
    protected_policy: dict,
    hospital_id: str,
    role: str,
    status: str,
    patient_id: str,
) -> dict:
    """
    Check whether a user's attributes match the protected policy.

    The authorization layer computes fresh commitments from the user's
    attributes and compares them to the stored protected representations.

    Parameters
    ----------
    protected_policy : dict from build_protected_policy()
    hospital_id      : user's hospital
    role             : user's role
    status           : expected consent status ('ACTIVE')
    patient_id       : patient being accessed

    Returns
    -------
    dict:
        'match'            : bool — all attributes match
        'hospital_match'   : bool
        'role_match'       : bool
        'status_match'     : bool
        'patient_match'    : bool
    """
    hospital_match = hmac.compare_digest(
        _commit(hospital_id), protected_policy.get('protected_hospital', '')
    )
    role_match = hmac.compare_digest(
        _commit(role), protected_policy.get('protected_role', '')
    )
    status_match = hmac.compare_digest(
        _commit(status), protected_policy.get('protected_status', '')
    )
    patient_match = hmac.compare_digest(
        _commit(patient_id), protected_policy.get('protected_patient', '')
    )

    return {
        'match':          hospital_match and role_match and status_match and patient_match,
        'hospital_match': hospital_match,
        'role_match':     role_match,
        'status_match':   status_match,
        'patient_match':  patient_match,
    }


def build_patient_policy_summary(patient_id: str, consent_policies: list) -> list:
    """
    Build protected policy representations for all consent entries of a patient.

    Parameters
    ----------
    patient_id       : str
    consent_policies : list of dicts from consent_service.get_all_policies()

    Returns
    -------
    list of protected policy dicts
    """
    result = []
    for p in consent_policies:
        pp = build_protected_policy(
            patient_id  = patient_id,
            hospital_id = p.get('hospital_id', ''),
            role        = p.get('role', ''),
            status      = p.get('status', 'REVOKED'),
        )
        result.append(pp)
    return result
