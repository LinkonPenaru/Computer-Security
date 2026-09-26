"""
services/consent_service.py
============================
Consent policy management — grant and revoke hospital/role access.

The consent model is:
  (patient_hash  ×  hospital_id  ×  role)  →  granted | revoked

This gives fine-grained control:
  PATIENT_001 can allow Hospital_A/Doctor but deny Hospital_A/Nurse.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db
from services import audit_service


def get_policy(patient_hash: str, hospital_id: str, role: str) -> dict | None:
    """
    Return the consent policy record for (patient × hospital × role), or None.
    """
    return db.fetchone(
        """SELECT * FROM consent_policies
           WHERE patient_hash=? AND hospital_id=? AND role=?""",
        (patient_hash, hospital_id, role),
    )


def get_all_policies(patient_hash: str) -> list:
    """Return all consent policy entries for a given patient_hash."""
    return db.fetchall(
        "SELECT * FROM consent_policies WHERE patient_hash=? ORDER BY hospital_id, role",
        (patient_hash,),
    )


def is_access_granted(patient_hash: str, hospital_id: str, role: str) -> bool:
    """
    Return True if a valid, active consent grants access.

    Access is granted when:
      access_granted = 1  AND  status = 'ACTIVE'
      AND (valid_until IS NULL OR valid_until > now())
    """
    row = db.fetchone(
        """SELECT access_granted, status, valid_until
           FROM consent_policies
           WHERE patient_hash=? AND hospital_id=? AND role=?""",
        (patient_hash, hospital_id, role),
    )
    if row is None:
        return False  # no policy = no access
    if row["status"] != "ACTIVE":
        return False
    if row["access_granted"] != 1:
        return False
    if row["valid_until"]:
        from datetime import datetime
        try:
            expiry = datetime.fromisoformat(row["valid_until"])
            if datetime.now() > expiry:
                return False
        except ValueError:
            pass
    return True


def grant(patient_hash: str, hospital_id: str, role: str,
          valid_until: str = None, actor: str = "system"):
    """
    Grant (or re-activate) access for (patient × hospital × role).

    Parameters
    ----------
    patient_hash : str — SHA-256 hash of the patient ID
    hospital_id  : str — e.g. "Hospital_A"
    role         : str — e.g. "Doctor"
    valid_until  : str — ISO datetime string, or None (no expiry)
    actor        : str — who performed the grant (for audit)
    """
    existing = get_policy(patient_hash, hospital_id, role)
    if existing:
        db.execute(
            """UPDATE consent_policies
               SET access_granted=1, status='ACTIVE',
                   valid_until=?, updated_at=datetime('now')
               WHERE patient_hash=? AND hospital_id=? AND role=?""",
            (valid_until, patient_hash, hospital_id, role),
        )
    else:
        db.execute(
            """INSERT INTO consent_policies
                   (patient_hash, hospital_id, role, access_granted, valid_until, status)
               VALUES (?, ?, ?, 1, ?, 'ACTIVE')""",
            (patient_hash, hospital_id, role, valid_until),
        )

    audit_service.log(
        "CONSENT_GRANTED",
        user_id=actor,
        patient_hash=patient_hash,
        details=f"Granted: hospital={hospital_id}, role={role}, until={valid_until or 'no expiry'}",
        success=True,
    )


def revoke(patient_hash: str, hospital_id: str, role: str, actor: str = "system"):
    """
    Revoke access for (patient × hospital × role).

    IMPORTANT NOTE (demonstrated to teacher):
      Revocation prevents all FUTURE decryption requests.
      It cannot erase data that was already downloaded in plaintext.
      The security guarantee is: no new authorized access after revocation.
    """
    db.execute(
        """UPDATE consent_policies
           SET access_granted=0, status='REVOKED', updated_at=datetime('now')
           WHERE patient_hash=? AND hospital_id=? AND role=?""",
        (patient_hash, hospital_id, role),
    )

    audit_service.log(
        "CONSENT_REVOKED",
        user_id=actor,
        patient_hash=patient_hash,
        details=f"Revoked: hospital={hospital_id}, role={role}",
        success=True,
    )


def get_consent_summary(patient_hash: str) -> dict:
    """
    Return a structured summary of all consent decisions for a patient.
    Useful for the dashboard display.
    """
    policies = get_all_policies(patient_hash)
    summary = {}
    for p in policies:
        key = f"{p['hospital_id']}::{p['role']}"
        summary[key] = {
            "hospital_id":    p["hospital_id"],
            "role":           p["role"],
            "access_granted": bool(p["access_granted"]),
            "status":         p["status"],
            "valid_until":    p["valid_until"],
            "updated_at":     p["updated_at"],
        }
    return summary
