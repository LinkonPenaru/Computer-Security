"""
services/authorization_service.py
===================================
Authorization engine — evaluates four conditions for every access request.

Decision logic:
    ALLOW  ⟺  HospitalMatch  AND  RoleMatch  AND  ConsentActive  AND  TimeValid

The result is returned as a structured dict showing each condition separately
so the teacher dashboard can display them one by one.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
from database import db
from services import audit_service, consent_service


def check_authorization(user_id: str, patient_hash: str) -> dict:
    """
    Evaluate whether user_id is authorized to access patient_hash's EHR.

    Returns
    -------
    dict:
        hospital_match  : bool
        role_match      : bool
        consent_active  : bool
        time_valid      : bool
        allowed         : bool  (True iff ALL four are True)
        reason          : str   (human-readable explanation)
        user_role       : str
        user_hospital   : str
    """
    # ── 1. Load the requesting user ─────────────────────────────────────────
    user = db.fetchone("SELECT * FROM users WHERE user_id=?", (user_id,))
    if user is None:
        result = _deny_result("Unknown user", "", "")
        _log(user_id, patient_hash, result)
        return result

    user_hospital = user["hospital_id"]
    user_role     = user["role"]

    # ── 2. Hospital match ────────────────────────────────────────────────────
    # The consent policy lists which hospitals are allowed.
    # We check whether the user's hospital appears in active consents.
    consent = consent_service.get_policy(patient_hash, user_hospital, user_role)
    hospital_match = consent is not None

    # ── 3. Role match ────────────────────────────────────────────────────────
    # The consent is per-role; a Doctor entry does NOT cover Nurses.
    role_match = hospital_match  # same consent record implies role matched

    # ── 4. Consent active ────────────────────────────────────────────────────
    consent_active = consent_service.is_access_granted(
        patient_hash, user_hospital, user_role
    )

    # ── 5. Time valid ────────────────────────────────────────────────────────
    # Check optional valid_until on the consent record.
    time_valid = True
    if consent and consent.get("valid_until"):
        try:
            expiry = datetime.fromisoformat(consent["valid_until"])
            time_valid = datetime.now() <= expiry
        except ValueError:
            time_valid = True   # malformed timestamp → treat as no expiry

    # ── 6. Final decision ────────────────────────────────────────────────────
    allowed = hospital_match and role_match and consent_active and time_valid

    if allowed:
        reason = "All authorization conditions satisfied."
    else:
        reasons = []
        if not hospital_match:
            reasons.append(f"Hospital '{user_hospital}' not in patient's allowed list.")
        if not role_match:
            reasons.append(f"Role '{user_role}' not permitted by patient consent.")
        if not consent_active:
            reasons.append("Patient consent has been revoked or is inactive.")
        if not time_valid:
            reasons.append("Consent validity period has expired.")
        reason = " | ".join(reasons)

    result = {
        "hospital_match": hospital_match,
        "role_match":     role_match,
        "consent_active": consent_active,
        "time_valid":     time_valid,
        "allowed":        allowed,
        "reason":         reason,
        "user_role":      user_role,
        "user_hospital":  user_hospital,
    }

    _log(user_id, patient_hash, result)
    return result


def _deny_result(reason: str, role: str, hospital: str) -> dict:
    return {
        "hospital_match": False,
        "role_match":     False,
        "consent_active": False,
        "time_valid":     True,
        "allowed":        False,
        "reason":         reason,
        "user_role":      role,
        "user_hospital":  hospital,
    }


def _log(user_id: str, patient_hash: str, result: dict):
    event = "AUTH_GRANTED" if result["allowed"] else "AUTH_DENIED"
    audit_service.log(
        event_type   = event,
        user_id      = user_id,
        patient_hash = patient_hash,
        details      = result["reason"],
        success      = result["allowed"],
    )
