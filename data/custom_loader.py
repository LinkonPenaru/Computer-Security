"""
data/custom_loader.py
=====================
Loads a user-supplied CSV file into the MASE-SE system.

Expected CSV format (see CUSTOM_DATASET_TEMPLATE.csv):
    record_id, patient_id, hospital_id, department, diagnosis, icd_code,
    admit_date, discharge_date, sensitivity, keywords, notes

Rules:
  - patient_id   must be one of: PATIENT_001 … PATIENT_006
  - hospital_id  must be one of: Hospital_A, Hospital_B, Hospital_C
  - sensitivity  must be one of: LOW, MEDIUM, HIGH
  - admit_date   format: YYYY-MM-DD
  - keywords     comma-separated list, e.g.  "diabetes,glucose,insulin"
  - record_id    must be unique across all rows

Usage (CLI):
    py data/custom_loader.py path/to/your_data.csv

Usage (Python):
    from data.custom_loader import load_custom_csv
    result = load_custom_csv("path/to/your_data.csv")
"""

import sys
import os
import csv
import json
import io

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from database import db
from crypto import key_manager, ehr_encryption, searchable_encryption, hashing

# ── Constants ────────────────────────────────────────────────────────────────

VALID_PATIENTS    = {"PATIENT_001", "PATIENT_002", "PATIENT_003",
                     "PATIENT_004", "PATIENT_005", "PATIENT_006"}
VALID_HOSPITALS   = {"Hospital_A", "Hospital_B", "Hospital_C"}
VALID_SENSITIVITY = {"LOW", "MEDIUM", "HIGH"}

REQUIRED_COLUMNS  = {
    "record_id", "patient_id", "hospital_id", "department",
    "diagnosis",  "admit_date", "sensitivity", "keywords",
}

# ── Template CSV content ─────────────────────────────────────────────────────

TEMPLATE_CSV = """\
record_id,patient_id,hospital_id,department,diagnosis,icd_code,admit_date,discharge_date,sensitivity,keywords,notes
CUSTOM_001,PATIENT_001,Hospital_A,Cardiology,Type 2 Diabetes,E11,2024-01-15,2024-01-20,HIGH,"diabetes,glucose,insulin",Patient admitted with high blood sugar
CUSTOM_002,PATIENT_001,Hospital_A,Emergency,Hypertension,I10,2024-02-10,2024-02-12,MEDIUM,"hypertension,blood pressure",Elevated BP on routine checkup
CUSTOM_003,PATIENT_002,Hospital_A,Neurology,Ischemic Stroke,I63,2024-03-05,2024-03-15,HIGH,"stroke,ischemic,brain",Admitted to neurology after TIA episode
CUSTOM_004,PATIENT_003,Hospital_B,Pulmonology,Pneumonia,J18,2024-01-22,2024-01-28,MEDIUM,"pneumonia,respiratory,infection",Community-acquired pneumonia
CUSTOM_005,PATIENT_003,Hospital_B,ICU,Sepsis,A41,2024-04-01,2024-04-10,HIGH,"sepsis,infection,fever",Sepsis secondary to UTI
CUSTOM_006,PATIENT_004,Hospital_B,Nephrology,Chronic Kidney Disease,N18,2024-05-12,2024-05-18,HIGH,"kidney,renal,creatinine",CKD stage 3 follow-up
CUSTOM_007,PATIENT_005,Hospital_C,Oncology,Colon Cancer,C18,2024-06-01,2024-06-08,HIGH,"cancer,oncology,colon",Post-chemotherapy evaluation
CUSTOM_008,PATIENT_005,Hospital_C,General Medicine,Atrial Fibrillation,I48,2024-07-15,2024-07-17,MEDIUM,"atrial fibrillation,cardiac,arrhythmia",Palpitations and irregular heartbeat
CUSTOM_009,PATIENT_006,Hospital_C,Orthopedics,Hip Fracture,S72,2024-08-03,2024-08-14,LOW,"fracture,hip,orthopedic",Fall-related hip fracture in elderly patient
CUSTOM_010,PATIENT_006,Hospital_C,Gastroenterology,GI Bleed,K92,2024-09-20,2024-09-23,HIGH,"gastrointestinal,bleed,hemoglobin",Upper GI bleed requiring transfusion
"""


# ── Validation ───────────────────────────────────────────────────────────────

def validate_row(row: dict, row_num: int) -> list:
    """Return list of error strings for this row (empty = valid)."""
    errors = []

    # Required columns present
    for col in REQUIRED_COLUMNS:
        if not row.get(col, "").strip():
            errors.append(f"Row {row_num}: missing required column '{col}'")

    if errors:
        return errors  # skip further checks if basics missing

    pid  = row["patient_id"].strip()
    hosp = row["hospital_id"].strip()
    sens = row["sensitivity"].strip().upper()
    rid  = row["record_id"].strip()
    dt   = row["admit_date"].strip()

    if pid not in VALID_PATIENTS:
        errors.append(f"Row {row_num} [{rid}]: patient_id '{pid}' invalid. Must be one of {sorted(VALID_PATIENTS)}")
    if hosp not in VALID_HOSPITALS:
        errors.append(f"Row {row_num} [{rid}]: hospital_id '{hosp}' invalid. Must be one of {sorted(VALID_HOSPITALS)}")
    if sens not in VALID_SENSITIVITY:
        errors.append(f"Row {row_num} [{rid}]: sensitivity '{sens}' invalid. Must be LOW, MEDIUM, or HIGH")
    if len(dt) != 10 or dt[4] != '-' or dt[7] != '-':
        errors.append(f"Row {row_num} [{rid}]: admit_date '{dt}' must be YYYY-MM-DD")
    if not rid:
        errors.append(f"Row {row_num}: record_id is empty")

    return errors


# ── Loader ───────────────────────────────────────────────────────────────────

def load_custom_csv(csv_path_or_content: str, is_content: bool = False) -> dict:
    """
    Load a custom CSV into the MASE-SE system.

    Args:
        csv_path_or_content: file path OR raw CSV string
        is_content:          True if passing raw CSV string directly

    Returns:
        dict with keys: success, records, search_index, errors, warnings, message
    """
    db.init_db()

    # Load hospital keys
    stored_keys = {}
    rows_keys = db.fetchall("SELECT hospital_id, ehr_key_b64, search_key_b64 FROM hospital_keys")
    if not rows_keys:
        return {"success": False, "message": "Hospital keys not found. Run: py database/seed.py first."}

    for row in rows_keys:
        stored_keys[row["hospital_id"]] = {
            "ehr_key":    row["ehr_key_b64"],    # base64 string — what initialize_keys expects
            "search_key": row["search_key_b64"],
        }
    key_manager.initialize_keys(stored_keys)

    # Read CSV
    try:
        if is_content:
            reader = csv.DictReader(io.StringIO(csv_path_or_content))
        else:
            f = open(csv_path_or_content, "r", encoding="utf-8")
            reader = csv.DictReader(f)
    except FileNotFoundError:
        return {"success": False, "message": f"File not found: {csv_path_or_content}"}
    except Exception as e:
        return {"success": False, "message": f"Could not read CSV: {e}"}

    rows       = list(reader)
    all_errors = []
    warnings   = []

    # Validate columns
    if not rows:
        return {"success": False, "message": "CSV file is empty."}

    header = set(rows[0].keys())
    missing_cols = REQUIRED_COLUMNS - header
    if missing_cols:
        return {
            "success": False,
            "message": f"CSV is missing required columns: {sorted(missing_cols)}. "
                       f"Download the template to see the correct format.",
            "errors":  [f"Missing columns: {sorted(missing_cols)}"],
        }

    # Validate rows
    seen_ids = set()
    valid_rows = []
    for i, row in enumerate(rows, start=2):
        rid = row.get("record_id", "").strip()
        if rid in seen_ids:
            all_errors.append(f"Row {i}: duplicate record_id '{rid}'")
            continue
        seen_ids.add(rid)
        errs = validate_row(row, i)
        if errs:
            all_errors.extend(errs)
        else:
            valid_rows.append(row)

    if all_errors and not valid_rows:
        return {"success": False, "errors": all_errors,
                "message": f"Validation failed — {len(all_errors)} error(s). No records loaded."}

    if all_errors:
        warnings.append(f"{len(all_errors)} row(s) had errors and were skipped.")

    # Use a single connection for the entire transaction to avoid 'database is locked' errors and speed up loading
    conn = db.get_connection()
    try:
        # Clear existing records and search index
        conn.execute("DELETE FROM ehr_records WHERE 1=1")
        conn.execute("DELETE FROM search_index WHERE 1=1")
    
        # Insert valid rows
        inserted   = 0
        index_rows = 0
    
        for row in valid_rows:
            record_id   = row["record_id"].strip()
            patient_id  = row["patient_id"].strip()
            hospital_id = row["hospital_id"].strip()
            department  = row["department"].strip()
            sensitivity = row["sensitivity"].strip().upper()
            admit_date  = row["admit_date"].strip()
            keywords_raw = row.get("keywords", "").strip()
            keywords    = [k.strip().lower() for k in keywords_raw.split(",") if k.strip()]
    
            # Build plaintext EHR JSON
            ehr_dict = {
                "record_id":      record_id,
                "patient_id":     patient_id,
                "hospital_id":    hospital_id,
                "department":     department,
                "diagnosis":      row.get("diagnosis", "").strip(),
                "icd_code":       row.get("icd_code", "").strip(),
                "admit_date":     admit_date,
                "discharge_date": row.get("discharge_date", "").strip(),
                "sensitivity":    sensitivity,
                "notes":          row.get("notes", "").strip(),
                "data_source":    "CUSTOM_UPLOAD",
            }
    
            ehr_key    = key_manager.get_ehr_key(hospital_id)
            search_key = key_manager.get_search_key(hospital_id)
            enc          = ehr_encryption.encrypt_ehr(json.dumps(ehr_dict), ehr_key)
            patient_hash = hashing.hash_user_id(patient_id)
    
            conn.execute(
                """INSERT OR REPLACE INTO ehr_records
                   (record_id, patient_hash, hospital_id, encrypted_ehr, nonce, tag,
                    admit_date, sensitivity, department)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (record_id, patient_hash, hospital_id,
                 enc["ciphertext"], enc["nonce"], enc["tag"],
                 admit_date, sensitivity, department)
            )
    
            # Build search index
            all_kw = keywords + [department.lower(), sensitivity.lower()]
            for kw in set(all_kw):
                if len(kw) >= 3:
                    token = searchable_encryption.generate_search_token(kw, search_key)
                    conn.execute(
                        "INSERT OR IGNORE INTO search_index (token, record_id, hospital_id) VALUES (?,?,?)",
                        (token, record_id, hospital_id)
                    )
                    index_rows += 1
    
            inserted += 1
            
        conn.commit()
    
        cur = conn.execute("SELECT COUNT(*) c FROM ehr_records")
        ehr_count = cur.fetchone()["c"]
        cur = conn.execute("SELECT COUNT(*) c FROM search_index")
        idx_count = cur.fetchone()["c"]
    finally:
        conn.close()

    return {
        "success":      True,
        "source":       "custom",
        "records":      ehr_count,
        "search_index": idx_count,
        "skipped":      len(rows) - inserted,
        "errors":       all_errors,
        "warnings":     warnings,
        "message":      f"Loaded {inserted} record(s) → {ehr_count} total in DB, {idx_count} search index entries.",
    }


def get_template_csv() -> str:
    """Return the template CSV string for download."""
    return TEMPLATE_CSV


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: py data/custom_loader.py <path_to_csv>")
        print("\nTo generate a template CSV:")
        print("  py -c \"from data.custom_loader import get_template_csv; open('template.csv','w').write(get_template_csv())\"")
        sys.exit(1)

    path = sys.argv[1]
    result = load_custom_csv(path)
    if result["success"]:
        print(f"SUCCESS: {result['message']}")
        if result.get("warnings"):
            for w in result["warnings"]:
                print(f"  WARNING: {w}")
    else:
        print(f"FAILED: {result['message']}")
        for e in result.get("errors", []):
            print(f"  ERROR: {e}")
