"""
data/dummy_dataset.py
=====================
Generates a clean, self-contained dummy EHR dataset for demonstration
and GitHub users who do not have access to the MIMIC-IV dataset.

Records are entirely fictional — no real patient data is used.
The schema and field names match the MIMIC-IV preprocessor output exactly,
so the same encryption pipeline, search index, and authorization system apply.

Usage:
    py data/dummy_dataset.py

What this does:
    1. Seeds the database (users, hospitals, patients, consent policies).
    2. Creates 500 fictional EHR records spread across 3 hospitals & 6 patients.
    3. Encrypts every record with AES-256-GCM.
    4. Builds the HMAC-SHA256 searchable keyword index.
    5. Logs progress to the console.

After running, start the app normally:
    py app.py
"""

import sys
import os
import random
import hashlib
import json
from datetime import datetime, timedelta

# ── path setup ──────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from database import db
from database.seed import seed               # reuse existing seed (users/hospitals/patients)
from crypto import key_manager, ehr_encryption, searchable_encryption, hashing
import base64

# ── Fictional data pools ─────────────────────────────────────────────────────

DEPARTMENTS = [
    "Cardiology", "Neurology", "Oncology", "Emergency", "Orthopedics",
    "Pulmonology", "Nephrology", "Gastroenterology", "ICU", "General Medicine",
]

DIAGNOSES = [
    {"name": "Type 2 Diabetes Mellitus",  "icd": "E11",  "keywords": ["diabetes", "glucose", "insulin", "hyperglycemia"]},
    {"name": "Essential Hypertension",    "icd": "I10",  "keywords": ["hypertension", "blood pressure", "hypertensive"]},
    {"name": "Congestive Heart Failure",  "icd": "I50",  "keywords": ["heart failure", "cardiac", "edema", "dyspnea"]},
    {"name": "Acute Myocardial Infarction","icd":"I21",  "keywords": ["myocardial", "infarction", "heart attack", "troponin"]},
    {"name": "Community-Acquired Pneumonia","icd":"J18", "keywords": ["pneumonia", "respiratory", "infection", "fever"]},
    {"name": "Chronic Kidney Disease",    "icd": "N18",  "keywords": ["kidney", "renal", "creatinine", "dialysis"]},
    {"name": "Sepsis",                    "icd": "A41",  "keywords": ["sepsis", "infection", "bacteremia", "fever"]},
    {"name": "Stroke (Ischemic)",         "icd": "I63",  "keywords": ["stroke", "ischemic", "brain", "neurological"]},
    {"name": "Chronic Obstructive Pulmonary Disease","icd":"J44","keywords": ["copd", "pulmonary", "respiratory", "bronchitis"]},
    {"name": "Acute Kidney Injury",       "icd": "N17",  "keywords": ["kidney", "acute", "renal", "creatinine"]},
    {"name": "Atrial Fibrillation",       "icd": "I48",  "keywords": ["atrial fibrillation", "cardiac", "arrhythmia"]},
    {"name": "Colon Cancer",              "icd": "C18",  "keywords": ["cancer", "oncology", "colon", "chemotherapy"]},
    {"name": "Gastrointestinal Bleed",    "icd": "K92",  "keywords": ["gastrointestinal", "bleed", "hemoglobin", "transfusion"]},
    {"name": "Urinary Tract Infection",   "icd": "N39",  "keywords": ["urinary", "infection", "uti", "bacteria"]},
    {"name": "Hip Fracture",              "icd": "S72",  "keywords": ["fracture", "hip", "orthopedic", "surgery"]},
]

FIRST_NAMES = ["James", "Emma", "Liam", "Sophia", "Noah", "Olivia",
               "William", "Ava", "Benjamin", "Isabella", "Lucas", "Mia"]
LAST_NAMES  = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
               "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez"]

HOSPITALS = ["Hospital_A", "Hospital_B", "Hospital_C"]
PATIENTS  = ["PATIENT_001", "PATIENT_002", "PATIENT_003",
             "PATIENT_004", "PATIENT_005", "PATIENT_006"]

# Map patients to their assigned hospital (from seed.py)
PATIENT_HOSPITAL = {
    "PATIENT_001": "Hospital_A",
    "PATIENT_002": "Hospital_A",
    "PATIENT_003": "Hospital_B",
    "PATIENT_004": "Hospital_B",
    "PATIENT_005": "Hospital_C",
    "PATIENT_006": "Hospital_C",
}

TOTAL_RECORDS = 500    # easy to run on any machine


def random_date(start_year=2020, end_year=2024):
    start = datetime(start_year, 1, 1)
    end   = datetime(end_year, 12, 31)
    delta = end - start
    return (start + timedelta(days=random.randint(0, delta.days))).strftime("%Y-%m-%d")


def generate_ehr_record(record_id: str, patient_id: str, hospital_id: str) -> dict:
    """
    Build a single fictional EHR record dict.
    Field names deliberately match what the MIMIC preprocessor produces.
    """
    diag      = random.choice(DIAGNOSES)
    dept      = random.choice(DEPARTMENTS)
    admit     = random_date()
    admit_dt  = datetime.strptime(admit, "%Y-%m-%d")
    discharge = (admit_dt + timedelta(days=random.randint(1, 21))).strftime("%Y-%m-%d")
    fn        = random.choice(FIRST_NAMES)
    ln        = random.choice(LAST_NAMES)
    age       = random.randint(18, 90)
    bp_sys    = random.randint(100, 180)
    bp_dia    = random.randint(60, 110)
    hr        = random.randint(55, 130)
    temp      = round(random.uniform(36.1, 39.5), 1)
    spo2      = random.randint(88, 100)

    return {
        "record_id":       record_id,
        "patient_id":      patient_id,
        "patient_name":    f"{fn} {ln}",          # fictional — not linked to real persons
        "age":             age,
        "gender":          random.choice(["M", "F"]),
        "hospital_id":     hospital_id,
        "department":      dept,
        "diagnosis":       diag["name"],
        "icd_code":        diag["icd"],
        "admit_date":      admit,
        "discharge_date":  discharge,
        "los_days":        (datetime.strptime(discharge, "%Y-%m-%d") - admit_dt).days,
        "blood_pressure":  f"{bp_sys}/{bp_dia} mmHg",
        "heart_rate":      f"{hr} bpm",
        "temperature":     f"{temp} °C",
        "spo2":            f"{spo2}%",
        "medications":     random.choice([
            "Metformin 500mg", "Lisinopril 10mg", "Atorvastatin 40mg",
            "Amoxicillin 500mg", "Furosemide 40mg", "Aspirin 81mg",
            "Insulin glargine", "Warfarin 5mg", "Omeprazole 20mg",
        ]),
        "sensitivity":     random.choice(["LOW", "MEDIUM", "HIGH"]),
        "keywords":        diag["keywords"],
        "notes":           f"Patient admitted to {dept} with {diag['name']}. "
                           f"Vitals stable on discharge. Follow-up scheduled.",
        "data_source":     "DUMMY_DATASET_v1",
    }


def load_dummy_dataset(progress_callback=None):
    """
    Main entry point — called by the API route or directly from CLI.
    Returns a summary dict.
    """
    print("\n" + "="*60)
    print("  MASE-SE — Dummy Dataset Loader")
    print("="*60)

    # 1. Init DB schema
    db.init_db()

    # 2. Seed users, hospitals, patients, consent policies (also initialises keys)
    print("\n[1/4] Seeding users, hospitals, patients, consent…")
    seed()

    # 3. Reload keys into key_manager from DB (pass as base64 strings — that's what initialize_keys expects)
    rows = db.fetchall("SELECT hospital_id, ehr_key_b64, search_key_b64 FROM hospital_keys")
    stored_keys = {}
    for row in rows:
        stored_keys[row["hospital_id"]] = {
            "ehr_key":    row["ehr_key_b64"],    # already base64 string
            "search_key": row["search_key_b64"],  # already base64 string
        }
    key_manager.initialize_keys(stored_keys)
    print(f"    Keys loaded for: {list(stored_keys.keys())}")

    # 4. Clear any previous dummy / MIMIC records (keep users/patients/consent)
    db.execute("DELETE FROM ehr_records WHERE 1=1")
    db.execute("DELETE FROM search_index WHERE 1=1")
    print("\n[2/4] Cleared old ehr_records and search_index.")

    # 5. Generate and encrypt records
    print(f"\n[3/4] Generating {TOTAL_RECORDS} fictional EHR records…")
    inserted = 0
    index_rows = 0
    random.seed(42)   # reproducible output

    for i in range(TOTAL_RECORDS):
        patient_id  = PATIENTS[i % len(PATIENTS)]
        hospital_id = PATIENT_HOSPITAL[patient_id]
        record_id   = f"DUMMY_{i+1:05d}"

        record = generate_ehr_record(record_id, patient_id, hospital_id)
        keywords = record.pop("keywords")

        # Encrypt
        ehr_key    = key_manager.get_ehr_key(hospital_id)
        search_key = key_manager.get_search_key(hospital_id)
        plaintext  = json.dumps(record)
        enc        = ehr_encryption.encrypt_ehr(plaintext, ehr_key)

        admit_date  = record["admit_date"]
        sensitivity = record["sensitivity"]
        department  = record["department"]
        patient_hash = hashing.hash_user_id(patient_id)

        # Insert encrypted record
        # enc keys: ciphertext, nonce, tag (all base64 strings)
        db.execute(
            """INSERT OR REPLACE INTO ehr_records
               (record_id, patient_hash, hospital_id, encrypted_ehr, nonce, tag,
                admit_date, sensitivity, department)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (record_id, patient_hash, hospital_id,
             enc["ciphertext"], enc["nonce"], enc["tag"],
             admit_date, sensitivity, department)
        )

        # Build search index
        all_kw = keywords + [department.lower(), sensitivity.lower(), admit_date[:4]]
        for kw in set(all_kw):
            token = searchable_encryption.generate_search_token(kw, search_key)
            db.execute(
                "INSERT OR IGNORE INTO search_index (token, record_id, hospital_id) VALUES (?,?,?)",
                (token, record_id, hospital_id)
            )
            index_rows += 1

        inserted += 1
        if inserted % 100 == 0:
            pct = int(inserted / TOTAL_RECORDS * 100)
            print(f"    Progress: {inserted}/{TOTAL_RECORDS} records ({pct}%)")
            if progress_callback:
                progress_callback(inserted, TOTAL_RECORDS)

    # 6. Summary
    ehr_count   = db.fetchone("SELECT COUNT(*) c FROM ehr_records")["c"]
    idx_count   = db.fetchone("SELECT COUNT(*) c FROM search_index")["c"]
    user_count  = db.fetchone("SELECT COUNT(*) c FROM users")["c"]
    print(f"\n[4/4] Done!")
    print(f"    EHR records  : {ehr_count}")
    print(f"    Search index : {idx_count} entries")
    print(f"    Users seeded : {user_count}")
    print(f"\n  Run: py app.py  →  http://localhost:5000")
    print("="*60 + "\n")

    return {
        "success":       True,
        "source":        "dummy",
        "records":       ehr_count,
        "search_index":  idx_count,
        "users":         user_count,
        "message":       f"Loaded {ehr_count} dummy EHR records and {idx_count} search index entries.",
    }


if __name__ == "__main__":
    load_dummy_dataset()
