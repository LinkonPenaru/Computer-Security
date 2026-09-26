"""
services/ehr_service.py
========================
EHR record operations — cloud representation, decryption, and metrics.

CRITICAL RULE:
  get_cloud_representation() NEVER returns plaintext EHR content.
  It returns only: record_id, patient_hash, hospital_id,
                   encrypted_ehr (ciphertext), nonce, tag,
                   admit_date, discharge_date, keyword_count, sensitivity.

  Plaintext is only produced by decrypt_record(), and ONLY after
  authorization_service confirms the requesting user is allowed.
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db
from crypto import ehr_encryption, key_manager
from services import audit_service


# ─── Cloud representation (NO plaintext) ───────────────────────────────────────

def get_cloud_representation(patient_hash: str) -> list:
    """
    Return the cloud-side view of all EHR records for a patient.
    Fields returned: record_id, patient_hash, hospital_id,
                     encrypted_ehr (first 40 chars + "…" for display),
                     nonce, keyword_count, admit_date, sensitivity.
    """
    rows = db.fetchall(
        """SELECT record_id, patient_hash, hospital_id,
                  encrypted_ehr, nonce, keyword_count,
                  admit_date, discharge_date, department, sensitivity
           FROM ehr_records WHERE patient_hash=? ORDER BY admit_date""",
        (patient_hash,),
    )
    # Truncate ciphertext for display — never show full plaintext
    result = []
    for r in rows:
        r["encrypted_ehr_preview"] = r["encrypted_ehr"][:40] + "…"
        del r["encrypted_ehr"]   # remove from cloud view
        result.append(r)
    return result


def get_records_by_ids(record_ids: list) -> list:
    """Return cloud representation for a list of record IDs (no plaintext)."""
    if not record_ids:
        return []
    placeholders = ",".join("?" * len(record_ids))
    rows = db.fetchall(
        f"""SELECT record_id, patient_hash, hospital_id,
                   encrypted_ehr, nonce, tag, keyword_count,
                   admit_date, discharge_date, department, sensitivity
            FROM ehr_records WHERE record_id IN ({placeholders})""",
        tuple(record_ids),
    )
    return rows


# ─── Authorized decryption ─────────────────────────────────────────────────────

def decrypt_record(record_id: str, requesting_user_id: str) -> dict:
    """
    Decrypt one EHR record.

    This function is called AFTER authorization_service.check_authorization()
    has returned allowed=True.  It is a separate explicit step so that
    the demo can clearly show:

      1. Authorization check → ALLOW
      2. Decrypt → plaintext EHR shown

    Returns
    -------
    dict:
        record_id   : str
        plaintext   : str  — decrypted EHR content
        decrypt_ms  : float — decryption time
    """
    t0 = time.perf_counter()

    row = db.fetchone(
        "SELECT * FROM ehr_records WHERE record_id=?", (record_id,)
    )
    if row is None:
        raise ValueError(f"Record '{record_id}' not found.")

    hospital_id = row["hospital_id"]
    ehr_key     = key_manager.get_ehr_key(hospital_id)

    plaintext = ehr_encryption.decrypt_ehr(
        row["encrypted_ehr"], row["nonce"], row["tag"], ehr_key
    )

    decrypt_ms = (time.perf_counter() - t0) * 1000

    audit_service.log(
        "EHR_DECRYPTED",
        user_id      = requesting_user_id,
        patient_hash = row["patient_hash"],
        details      = f"record_id={record_id}, hospital={hospital_id}, decrypt_ms={decrypt_ms:.2f}",
        success      = True,
    )

    return {
        "record_id":  record_id,
        "hospital_id": hospital_id,
        "plaintext":  plaintext,
        "admit_date": row["admit_date"],
        "department": row["department"],
        "decrypt_ms": round(decrypt_ms, 3),
    }


# ─── Statistics ────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    """Return high-level database statistics for the dashboard."""
    row = db.fetchone("SELECT COUNT(*) as total FROM ehr_records")
    total = row["total"] if row else 0

    by_hospital = db.fetchall(
        "SELECT hospital_id, COUNT(*) as cnt FROM ehr_records GROUP BY hospital_id"
    )

    by_sensitivity = db.fetchall(
        "SELECT sensitivity, COUNT(*) as cnt FROM ehr_records GROUP BY sensitivity"
    )

    idx_size = db.fetchone("SELECT COUNT(*) as cnt FROM search_index")

    return {
        "total_records":    total,
        "by_hospital":      {r["hospital_id"]: r["cnt"] for r in by_hospital},
        "by_sensitivity":   {r["sensitivity"]:  r["cnt"] for r in by_sensitivity},
        "index_entries":    idx_size["cnt"] if idx_size else 0,
    }
