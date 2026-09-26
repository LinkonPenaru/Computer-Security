"""
data/preprocess_mimic.py
=========================
Load, preprocess, encrypt, and index 10 000 MIMIC-IV EHR records.

Run once: py data/preprocess_mimic.py
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd

from config.settings import MIMIC_DATA_DIR, MAX_RECORDS
from database import db
from crypto import ehr_encryption, searchable_encryption as se, key_manager, hashing

HOSP_MAP    = {0: "Hospital_A", 1: "Hospital_B", 2: "Hospital_C"}
PATIENT_MAP = {i: f"PATIENT_{i+1:03d}" for i in range(6)}


def load_and_merge():
    print("Loading MIMIC-IV files …")
    patients   = pd.read_csv(os.path.join(MIMIC_DATA_DIR, "patients.csv.gz"),      compression="gzip")
    admissions = pd.read_csv(os.path.join(MIMIC_DATA_DIR, "admissions.csv.gz"),    compression="gzip")
    diagnoses  = pd.read_csv(os.path.join(MIMIC_DATA_DIR, "diagnoses_icd.csv.gz"), compression="gzip")
    d_icd      = pd.read_csv(os.path.join(MIMIC_DATA_DIR, "d_icd_diagnoses.csv.gz"), compression="gzip")

    print(f"  patients:   {len(patients):,}   admissions: {len(admissions):,}")
    print(f"  diagnoses:  {len(diagnoses):,}  d_icd: {len(d_icd):,}")

    # Join diagnoses with readable titles
    diag = diagnoses.merge(
        d_icd[["icd_code", "icd_version", "long_title"]],
        on=["icd_code", "icd_version"], how="left"
    )
    diag["long_title"] = diag["long_title"].fillna("Unknown Diagnosis")

    # Join with admissions for dates
    adm = admissions[["subject_id","hadm_id","admittime","dischtime","admission_type"]]
    merged = diag.merge(adm, on=["subject_id","hadm_id"], how="left")

    # Join patients for demographics
    pat = patients[["subject_id","anchor_age","gender"]]
    merged = merged.merge(pat, on="subject_id", how="left")

    return merged


def aggregate_admissions(merged: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate to one row per (subject_id, hadm_id).
    Uses pure vectorized pandas — no apply() with include_groups.
    """
    print("Aggregating by admission …")

    # Get first-row metadata per admission (fast dedup)
    meta_cols = [c for c in
                 ["subject_id","hadm_id","admittime","dischtime","anchor_age","gender","admission_type"]
                 if c in merged.columns]
    meta = merged[meta_cols].drop_duplicates(subset=["subject_id","hadm_id"]).copy()

    # Concatenate all diagnosis titles per admission
    titles = (
        merged.groupby(["subject_id","hadm_id"])["long_title"]
        .agg(lambda x: " ".join(x.tolist()))
        .reset_index()
        .rename(columns={"long_title": "all_titles"})
    )

    # Collect (icd_code, title) pairs per admission into a JSON-like string
    merged["diag_pair"] = merged["icd_code"].fillna("") + "||" + merged["long_title"].fillna("")
    diag_str = (
        merged.groupby(["subject_id","hadm_id"])["diag_pair"]
        .agg(lambda x: ";;".join(x.tolist()))
        .reset_index()
        .rename(columns={"diag_pair": "diag_pairs_str"})
    )

    result = meta.merge(titles,    on=["subject_id","hadm_id"], how="left")
    result = result.merge(diag_str, on=["subject_id","hadm_id"], how="left")
    return result.reset_index(drop=True)


def parse_diag_pairs(diag_str: str) -> list:
    """Parse the concatenated diagnosis string back into list of (code, title) tuples."""
    if not isinstance(diag_str, str) or not diag_str:
        return []
    pairs = []
    for item in diag_str.split(";;")[:10]:   # cap at 10 diagnoses per record
        parts = item.split("||", 1)
        code  = parts[0] if len(parts) > 0 else ""
        title = parts[1] if len(parts) > 1 else "Unknown"
        pairs.append((code, title))
    return pairs


def build_plaintext_ehr(row) -> str:
    """Build a human-readable EHR string from one admission row."""
    diag_pairs = parse_diag_pairs(row.get("diag_pairs_str", ""))
    lines = [
        "MIMIC-IV EHR Record",
        f"Patient ID  : P{row['subject_id']}",
        f"Admission   : {row['hadm_id']}",
        f"Admit Date  : {str(row.get('admittime','N/A'))[:10]}",
        f"Discharge   : {str(row.get('dischtime','N/A'))[:10]}",
        f"Age         : {int(row['anchor_age']) if pd.notna(row.get('anchor_age')) else 'N/A'}",
        f"Gender      : {row.get('gender','U')}",
        f"Admission Type: {row.get('admission_type','UNKNOWN')}",
        "",
        "Diagnoses:",
    ]
    for code, title in diag_pairs:
        lines.append(f"  [{code}] {title}")
    return "\n".join(lines)


def run_preprocessing():
    # Load keys from DB
    stored = db.fetchall("SELECT * FROM hospital_keys")
    if not stored:
        print("ERROR: Run 'py database/seed.py' first.")
        sys.exit(1)
    key_manager.initialize_keys({r["hospital_id"]: {
        "ehr_key": r["ehr_key_b64"], "search_key": r["search_key_b64"]
    } for r in stored})

    merged  = load_and_merge()
    grouped = aggregate_admissions(merged)
    grouped = grouped.head(MAX_RECORDS)
    print(f"Processing {len(grouped):,} admissions …")

    ehr_rows   = []
    index_rows = []

    for i, row in grouped.iterrows():
        subject_id  = int(row["subject_id"])
        hospital_id = HOSP_MAP[subject_id % 3]
        patient_id  = PATIENT_MAP[subject_id % 6]
        patient_hash = hashing.hash_user_id(patient_id)
        record_id   = f"REC_{i:05d}"

        admit_str = str(row.get("admittime", ""))[:10]
        disch_str = str(row.get("dischtime", ""))[:10]

        plaintext = build_plaintext_ehr(row)
        ehr_key   = key_manager.get_ehr_key(hospital_id)
        enc       = ehr_encryption.encrypt_ehr(plaintext, ehr_key)

        all_titles = str(row.get("all_titles", ""))
        kws        = se.extract_keywords_from_diagnosis(all_titles)
        search_key = key_manager.get_search_key(hospital_id)

        ehr_rows.append((
            record_id, patient_hash, hospital_id,
            enc["ciphertext"], enc["nonce"], enc["tag"],
            admit_str, disch_str, "General", "Confidential", len(kws),
        ))

        for kw in kws:
            token = se.generate_search_token(kw, search_key)
            index_rows.append((hospital_id, token, record_id))

        if (i + 1) % 1000 == 0:
            print(f"  … {i+1:,} records processed")

    print("Inserting into database …")
    db.executemany(
        """INSERT OR IGNORE INTO ehr_records
               (record_id, patient_hash, hospital_id, encrypted_ehr, nonce, tag,
                admit_date, discharge_date, department, sensitivity, keyword_count)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        ehr_rows,
    )
    print("Building search index …")
    db.executemany(
        "INSERT OR IGNORE INTO search_index (hospital_id, search_token, record_id) VALUES (?,?,?)",
        index_rows,
    )

    stats = db.fetchone("SELECT COUNT(*) c FROM ehr_records")
    idx   = db.fetchone("SELECT COUNT(*) c FROM search_index")
    print(f"\nDone! EHR records: {stats['c']:,}  |  Index entries: {idx['c']:,}")


if __name__ == "__main__":
    t0 = time.time()
    db.init_db()
    run_preprocessing()
    print(f"Total time: {time.time()-t0:.1f}s")
