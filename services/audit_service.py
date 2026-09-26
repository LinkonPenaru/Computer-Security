"""
services/audit_service.py
=========================
Application-level event logging.

Every security-relevant event is written to the audit_log table so the
teacher can see the EXACT sequence of operations during the demonstration.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db


def log(event_type: str,
        user_id: str = None,
        patient_hash: str = None,
        details: str = None,
        success: bool = True):
    """
    Write one event to the audit log.

    Parameters
    ----------
    event_type   : str  — e.g. "SEARCH", "AUTH_GRANTED", "CONSENT_REVOKED"
    user_id      : str  — the acting user (optional)
    patient_hash : str  — the patient whose record was accessed (optional)
    details      : str  — human-readable detail message
    success      : bool — True = success, False = failure / denial
    """
    db.execute(
        """INSERT INTO audit_log
               (event_type, user_id, patient_hash, details, success)
           VALUES (?, ?, ?, ?, ?)""",
        (event_type, user_id, patient_hash, details, 1 if success else 0),
    )


def get_recent(limit: int = 100) -> list:
    """Return the most recent audit events as a list of dicts."""
    return db.fetchall(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
        (limit,),
    )


def clear():
    """Clear all audit entries (for testing)."""
    db.execute("DELETE FROM audit_log")
