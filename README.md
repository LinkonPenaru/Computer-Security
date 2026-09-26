# MASE-SE — Multi-Authority Attribute-Based Searchable Encryption for Secure Cross-Hospital EHR Sharing

> **Academic Research Prototype** — 11th Trimester CS Research Project

MASE-SE is a cryptographic security prototype that demonstrates how Electronic Health Records (EHRs) can be securely stored, searched, and shared across multiple hospitals without ever exposing plaintext patient data to the storage layer. It is built around three practical cryptographic mechanisms — AES-256-GCM authenticated encryption, HMAC-SHA256 protected keyword search, and a four-condition attribute-based authorization engine — all presented through an interactive web dashboard designed for live demonstration.

The system addresses a real research problem: how can a cloud storage provider serve EHR search queries across hospitals without seeing either the patient records or the keywords being searched? MASE-SE answers this question with a working prototype backed by 10,000 real (de-identified) clinical records from the MIMIC-IV dataset.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Main Objectives](#2-main-objectives)
3. [System Architecture](#3-system-architecture)
4. [Working Mechanism](#4-working-mechanism)
5. [Cryptographic Techniques](#5-cryptographic-techniques)
6. [Security Properties](#6-security-properties)
7. [Dataset — MIMIC-IV](#7-dataset--mimic-iv)
8. [Running Without MIMIC-IV (Dummy Data)](#8-running-without-mimic-iv-dummy-data)
9. [Repository Structure](#9-repository-structure)
10. [Installation](#10-installation)
11. [Quick Start](#11-quick-start)
12. [Example Workflow](#12-example-workflow)
13. [Reproducing the Project](#13-reproducing-the-project)
14. [Limitations](#14-limitations)
15. [Future Improvements](#15-future-improvements)
16. [Disclaimer](#16-disclaimer)
17. [Attribution and Dataset Citation](#17-attribution-and-dataset-citation)

---

## 1. Project Overview

### Problem Statement

Modern healthcare increasingly requires patient records to be accessible across multiple hospitals and clinical teams. However, centralizing EHR data in a shared cloud introduces serious privacy risks: the cloud operator, a compromised administrator, or an unauthorized clinician could read sensitive diagnoses, medication histories, or demographic information directly from storage.

Three specific challenges drive this project:

- **Confidentiality of stored data**: How do you store EHRs in a cloud database without the database server reading them?
- **Privacy-preserving search**: How does a doctor search for "diabetes" records without sending the word "diabetes" to the cloud?
- **Fine-grained access control**: How does a patient decide that Hospital A's doctors may access her record, Hospital B's nurses may not, and this permission can be revoked at any time?

### What MASE-SE Does

MASE-SE simulates a three-hospital cloud environment where:

- Every EHR is **encrypted with AES-256-GCM** before being stored. The cloud holds only ciphertext; the plaintext is never written to disk.
- Every searchable keyword is converted into an **HMAC-SHA256 token** before the index is built. A search query sends the token, not the word, to the cloud.
- Every access request is evaluated by a **four-condition authorization engine**: the requester's hospital, role, patient consent status, and consent time validity must all be satisfied before decryption is permitted.
- Patients hold **live consent policies** that can be granted or revoked through the dashboard, with immediate effect on all subsequent searches.
- Every security event — search requests, authorization decisions, consent changes, decryptions — is recorded in an **audit log**.

This is a **cryptography and security demonstration system**. It does not perform disease prediction, diagnosis, or any machine-learning inference.

---

## 2. Main Objectives

The following objectives are implemented in the current codebase:

| # | Objective | Status |
|---|-----------|--------|
| 1 | Protect patient identity using one-way SHA-256 hashing | ✅ Implemented |
| 2 | Encrypt all EHR content using AES-256-GCM authenticated encryption | ✅ Implemented |
| 3 | Enable keyword search over encrypted records using HMAC-SHA256 trapdoor tokens | ✅ Implemented |
| 4 | Enforce per-patient, per-hospital, per-role consent policies | ✅ Implemented |
| 5 | Support real-time consent revocation with immediate effect | ✅ Implemented |
| 6 | Record every access attempt in a tamper-evident audit log | ✅ Implemented |
| 7 | Demonstrate the full authorization workflow through an interactive dashboard | ✅ Implemented |
| 8 | Load and encrypt 10,000 real (de-identified) MIMIC-IV clinical records | ✅ Implemented |
| 9 | Measure and display real cryptographic performance benchmarks | ✅ Implemented |
| 10 | Provide placeholders for MPC/Shamir key sharing (future extension) | 🔲 Stubbed / Future |

---

## 3. System Architecture

The system is composed of six layers. Data moves through them sequentially during both setup and at search/access time.

```
┌──────────────────────────────────────────────────────────┐
│                    WEB DASHBOARD (Flask)                 │
│         templates/index.html + static/js/app.js          │
│  7 sections: Overview | Users | Cloud View | Search &    │
│  Authorization | Consent Management | Audit | Performance│
└────────────────────────────┬─────────────────────────────┘
                             │ HTTP / JSON
┌────────────────────────────▼─────────────────────────────┐
│                   FLASK API LAYER (app.py)               │
│  Routes: /api/search  /api/decrypt  /api/patients/...    │
│          /api/audit   /api/performance  /api/stats       │
└──────┬──────────────────────────────────┬────────────────┘
       │                                  │
┌──────▼──────────┐            ┌──────────▼───────────────┐
│  CRYPTO LAYER   │            │    SERVICE LAYER         │
│  crypto/        │            │    services/             │
│  ──────────     │            │    ─────────────         │
│  hashing.py     │            │    ehr_service.py        │
│  (SHA-256)      │            │    search_service.py     │
│                 │            │    authorization_        │
│  ehr_encryption │            │    service.py            │
│  .py (AES-256-  │            │    consent_service.py    │
│  GCM)           │            │    audit_service.py      │
│                 │            └──────────┬───────────────┘
│  searchable_    │                       │
│  encryption.py  │            ┌──────────▼────────────────┐
│  (HMAC-SHA256)  │            │   DATABASE LAYER          │
│                 │            │   database/               │
│  key_manager.py │            │   ──────────              │
│  (per-hospital  │◄───────────│   db.py (SQLite schema)   │
│   keys + MPC    │            │   seed.py                 │
│   stubs)        │            │   mase_se.db (runtime)    │
└─────────────────┘            └───────────────────────────┘
                                          │
                               ┌──────────▼────────────────┐
                               │   DATA PIPELINE           │
                               │   data/                   │
                               │   preprocess_mimic.py     │
                               │   (reads hosp/*.csv.gz,   │
                               │    encrypts & indexes)    │
                               └───────────────────────────┘
```

### Component Responsibilities

| Component | File(s) | Responsibility |
|-----------|---------|----------------|
| **Flask API** | `app.py` | Receives HTTP requests, orchestrates services, returns JSON |
| **SHA-256 Hashing** | `crypto/hashing.py` | Converts real patient/user IDs into one-way hashes before cloud storage |
| **AES-256-GCM** | `crypto/ehr_encryption.py` | Encrypts and authenticates EHR plaintext; decrypts upon authorized access |
| **HMAC-SHA256 SE** | `crypto/searchable_encryption.py` | Generates trapdoor tokens for index building and protected keyword queries |
| **Key Manager** | `crypto/key_manager.py` | Holds per-hospital AES and HMAC keys in memory at runtime; stubs for future MPC |
| **EHR Service** | `services/ehr_service.py` | Returns cloud view (ciphertext only) or decrypts on authorization |
| **Search Service** | `services/search_service.py` | Converts keywords to HMAC tokens, queries the search_index table |
| **Authorization** | `services/authorization_service.py` | Evaluates 4-condition decision (hospital ∧ role ∧ consent ∧ time) |
| **Consent Service** | `services/consent_service.py` | Grants and revokes (patient × hospital × role) consent policies |
| **Audit Service** | `services/audit_service.py` | Appends timestamped events to audit_log; supports the audit dashboard |
| **Database** | `database/db.py` | SQLite schema with 7 tables; connection and query helpers |
| **Seed Script** | `database/seed.py` | One-time setup: generates keys, inserts 20 users, 6 patients, 54 consent policies |
| **Preprocessor** | `data/preprocess_mimic.py` | Loads 4 MIMIC-IV files, encrypts 10,000 records, builds HMAC search index |
| **Dashboard** | `templates/index.html`, `static/` | Single-page web application served by Flask |
| **Configuration** | `config/settings.py` | All paths and constants in one place |

---

## 4. Working Mechanism

### Phase 1 — System Setup (run once)

**Step 1 — Database initialization**
Running `py database/seed.py` creates the SQLite database at `database/mase_se.db` with all seven tables. It then:
- Generates two independent 256-bit cryptographic keys for each of the three simulated hospitals: one AES-256 key for encrypting EHRs, and one HMAC-SHA256 key for building the search index. These six keys are stored in the `hospital_keys` table.
- Inserts 20 simulated system actors: 9 Doctors (3 per hospital), 3 Nurses (1 per hospital), 2 Researchers, and 6 Patient actors.
- For each user, computes `SHA-256(user_id)` and stores only the hash in the `users` table.
- Inserts 54 initial consent policies covering every `(patient × hospital × role)` combination across all 6 patients.

**Step 2 — EHR encryption and index building**
Running `py data/preprocess_mimic.py` loads four MIMIC-IV gzip-compressed CSV files:

```
hosp/patients.csv.gz        → demographic data (age, gender)
hosp/admissions.csv.gz      → hospital admission records (dates, type)
hosp/diagnoses_icd.csv.gz   → ICD diagnosis codes per admission
hosp/d_icd_diagnoses.csv.gz → human-readable ICD code descriptions
```

These are merged into one record per hospital admission. For each of the first 10,000 admissions:
1. A plaintext EHR string is constructed (patient metadata + diagnosis titles).
2. The EHR string is encrypted with AES-256-GCM using the hospital's key. The ciphertext, nonce, and GCM tag are stored in `ehr_records`. **The plaintext is never written to the database.**
3. Keywords are extracted from the diagnosis titles (stopwords removed, short tokens filtered).
4. For each keyword, `HMAC-SHA256(hospital.search_key, keyword)` is computed, producing a 64-character hex token.
5. Each (token → record_id) mapping is stored in `search_index`. **The plaintext keyword is never stored in the index.**

Hospital assignment uses `subject_id % 3`. Patient actor assignment uses `subject_id % 6 + 1`.

### Phase 2 — Live Search and Authorization (interactive)

When a user submits a search from the dashboard:

```
User selects: DOCTOR_001, PATIENT_001, keyword = "diabetes"
                    │
                    ▼
1. HMAC-SHA256(Hospital_A.search_key, "diabetes") → token_X
   (Cloud receives token_X — not the word "diabetes")
                    │
                    ▼
2. Query: SELECT record_id FROM search_index WHERE search_token = token_X
   → [REC_00040, REC_00081, REC_00140, ...]
                    │
                    ▼
3. Filter: keep only records where patient_hash = SHA-256("PATIENT_001")
                    │
                    ▼
4. Authorization check — four conditions evaluated in order:
   ┌───────────────────────────────────────────────────────────┐
   │  Hospital Match: "Hospital_A" ∈ patient's active grants   │ ✓/✗
   │  Role Match:     "Doctor"     ∈ patient's role grants     │ ✓/✗
   │  Consent Active: status='ACTIVE' AND access_granted=1     │ ✓/✗
   │  Time Valid:     now() ≤ valid_until (or NULL=no expiry)  │ ✓/✗
   └───────────────────────────────────────────────────────────┘
   ALL FOUR MUST BE TRUE → ACCESS GRANTED
   ANY ONE FALSE          → ACCESS DENIED
                    │
          (if GRANTED)
                    ▼
5. Retrieve ciphertext + nonce + tag for matched record IDs.
   AES-256-GCM decrypt → plaintext EHR returned to the requester.
   All four conditions, decision, and decryption are recorded in audit_log.
```

### Consent Revocation

When a patient revokes access (e.g., Hospital_A / Doctor):
- `consent_policies` row is updated: `access_granted=0`, `status='REVOKED'`.
- The next identical search by DOCTOR_001 goes through the same four-condition check.
- Condition 3 (Consent Active) now returns False.
- ACCESS DENIED is returned. The ciphertext is never touched.
- The audit log records `CONSENT_REVOKED` and the subsequent `AUTH_DENIED`.

---

## 5. Cryptographic Techniques

### SHA-256 — Patient Identity Protection

**What it is:** SHA-256 is a one-way cryptographic hash function from the SHA-2 family. It produces a fixed 256-bit (64-character hex) digest from any input.

**Where it is used:** `crypto/hashing.py` — `hash_user_id()` and `verify_user_id()`.

**Why it is used here:** The cloud storage layer must never hold a real patient identifier. Before any patient or user record is stored in the database, its identifier is converted to `SHA-256(user_id)`. The system stores and queries only this hash. A patient's real ID (`PATIENT_001`) never appears in `ehr_records`, `consent_policies`, or `search_index`.

**What happens during execution:**
```
"PATIENT_001"  →  SHA-256  →  "a3f2b8c1d4e5f6..."  (64 hex chars, stored in DB)
```
Reversal is computationally infeasible. Verification is done by hashing the candidate again and comparing.

---

### AES-256-GCM — Authenticated EHR Encryption

**What it is:** AES (Advanced Encryption Standard) in GCM (Galois/Counter Mode) is a symmetric authenticated encryption scheme. AES-256 uses a 256-bit key. GCM mode simultaneously provides confidentiality (no one without the key can read the ciphertext) and data authentication (any tampering with the ciphertext is detected).

**Where it is used:** `crypto/ehr_encryption.py` — `encrypt_ehr()` and `decrypt_ehr()`. Called by `data/preprocess_mimic.py` during setup and by `services/ehr_service.py` during authorized decryption.

**Why it is used here:** EHR plaintext must be unreadable to the cloud operator and to unauthorized requesters. AES-256-GCM provides both confidentiality (attackers cannot read the record) and integrity (any modification to the stored ciphertext causes decryption to fail with a `ValueError`).

**What happens during execution:**
```
At encryption time:
  nonce  ← 16 random bytes (fresh per call — never reused)
  cipher ← AES-256-GCM(hospital.ehr_key, nonce)
  (ciphertext, tag) ← cipher.encrypt_and_digest(plaintext_bytes)
  → stored in DB: ciphertext_b64, nonce_b64, tag_b64

At decryption time:
  cipher ← AES-256-GCM(hospital.ehr_key, nonce)
  plaintext ← cipher.decrypt_and_verify(ciphertext, tag)
  → if tag mismatch: raises ValueError (tampering detected)
```

The nonce is unique per encryption call, preventing nonce-reuse attacks. All three components (ciphertext, nonce, tag) are stored in base64 encoding in `ehr_records`.

**Implementation library:** PyCryptodome (`Crypto.Cipher.AES`).

---

### HMAC-SHA256 — Searchable Symmetric Encryption

**What it is:** HMAC (Hash-based Message Authentication Code) with SHA-256 is a pseudorandom function that produces a keyed digest. Given the same key and input, it always produces the same output. Without the key, the output is indistinguishable from random.

**Where it is used:** `crypto/searchable_encryption.py` — `generate_search_token()`, `extract_keywords_from_diagnosis()`. Called during `data/preprocess_mimic.py` (index building) and `services/search_service.py` (query time).

**Why it is used here:** The cloud must be able to match search queries to records without seeing the plaintext keywords. The HMAC key is held by the application layer; the cloud sees only tokens. This construction is a form of Searchable Symmetric Encryption (SSE) — specifically the simple token-based scheme where `SearchToken = HMAC(K_search, keyword)`.

**What happens during execution:**
```
Index building (at setup):
  keyword "diabetes"  →  HMAC-SHA256(Hospital_A.search_key, "diabetes")
                      →  "a3f2b8c1d4e5..."  (64 hex chars, stored in search_index)

Search query (at runtime):
  user types "diabetes"  →  HMAC-SHA256(Hospital_A.search_key, "diabetes")
                         →  "a3f2b8c1d4e5..."  (same token, cloud-side lookup)
  → returns matching record IDs
```

Multiple keywords produce multiple tokens. The search engine performs a conjunctive AND-search: a record must match all tokens to be returned.

**What the cloud never sees:** The plaintext word "diabetes" or any other keyword.

---

### Per-Hospital Key Management

**Where it is used:** `crypto/key_manager.py`.

Each of the three simulated hospitals holds two independent 256-bit keys: one AES-256 key for EHR encryption and one HMAC-SHA256 key for the search index. Keys are generated by `Crypto.Random.get_random_bytes(32)`, stored base64-encoded in `hospital_keys`, and loaded into memory at application startup by `initialize_keys()`.

> **Important distinction**: This is a prototype-level key management approach. In the planned 40% extension, these hospital keys would be replaced by Shamir (2-of-3) secret shares distributed across hospital authorities, so that no single party holds a complete key. The stub functions `mpc_issue_key_share()` and `mpc_reconstruct_key()` in `key_manager.py` mark the exact insertion points for this extension.

---

## 6. Security Properties

### Implemented in This Prototype

| Property | Mechanism | Where |
|----------|-----------|-------|
| **EHR Confidentiality** | AES-256-GCM encryption; no plaintext stored | `ehr_records` table; `ehr_encryption.py` |
| **EHR Integrity** | GCM authentication tag; decryption fails on tampered ciphertext | `ehr_encryption.decrypt_ehr()` raises `ValueError` |
| **Patient Identity Protection** | SHA-256 one-way hashing of all patient/user IDs | `hashing.py`; all DB tables use `patient_hash` |
| **Keyword Confidentiality** | HMAC-SHA256 search tokens; plaintext keywords never in index | `searchable_encryption.py`; `search_index` table |
| **Access Control** | 4-condition attribute-based authorization (hospital ∧ role ∧ consent ∧ time) | `authorization_service.py` |
| **Consent Management** | Real database state; revocation takes effect on next query | `consent_service.py` |
| **Audit Trail** | Every authorization attempt, consent change, and decryption is logged | `audit_service.py`; `audit_log` table |

### Outside the Scope of This Prototype

| Property | Status |
|----------|--------|
| MPC / threshold key distribution | Stubbed. Placeholders exist. Not cryptographically implemented. |
| Transport-layer encryption (HTTPS/TLS) | Not configured. The Flask server runs plain HTTP for local demonstration. |
| Production key storage (HSM, KMS) | Keys are stored base64-encoded in an SQLite file. Not production-safe. |
| Formal security proof | Not provided. This is a prototype, not a peer-reviewed cryptographic system. |
| Real-world healthcare compliance | Not assessed. HIPAA, GDPR, or similar compliance requires additional legal and technical review. |
| Revocation of data already decrypted | Consent revocation prevents future decryption. It cannot un-deliver records already retrieved. |

This system is **not production-ready**. Do not treat it as a deployable healthcare security solution without security auditing, formal analysis, and compliance review.

---

## 7. Dataset — MIMIC-IV

### What is MIMIC-IV

MIMIC-IV (Medical Information Mart for Intensive Care) is a large, de-identified database of clinical records collected from Beth Israel Deaconess Medical Center, published and maintained by MIT's Laboratory for Computational Physiology. It contains records for hundreds of thousands of ICU and hospital admissions, including diagnoses, vital signs, laboratory results, medications, and notes.

MIMIC-IV is **not an open-access dataset**. It is subject to a formal data use agreement and requires authorized access through PhysioNet.

### How This Project Uses MIMIC-IV

MASE-SE uses four files from the `hosp/` module of MIMIC-IV:

| File | Contents | Role in MASE-SE |
|------|----------|-----------------|
| `patients.csv.gz` | Subject ID, anchor age, gender | Patient demographics |
| `admissions.csv.gz` | Admission/discharge times, admission type | Record timestamps |
| `diagnoses_icd.csv.gz` | ICD diagnosis codes per admission | Diagnosis codes for each visit |
| `d_icd_diagnoses.csv.gz` | ICD code → readable title mapping | Human-readable diagnosis text |

These four files are merged, and the first 10,000 hospital admissions (by `subject_id` ordering) are encrypted and indexed. Hospital assignment is deterministic: `subject_id % 3` maps each admission to Hospital_A, Hospital_B, or Hospital_C.

### Repository Contains No MIMIC-IV Data

**This repository does not include any MIMIC-IV data.** The `hosp/` directory (where the dataset files must be placed) is excluded from version control via `.gitignore`.

### How to Obtain Authorized Access to MIMIC-IV

To reproduce the project using the real MIMIC-IV dataset, you must complete the following steps through official channels:

1. **Complete CITI Program training** — specifically the "Data or Specimens Only Research" course or the CITI course required by PhysioNet. This is a mandatory training in research ethics and data privacy.
   - CITI Program: [https://about.citiprogram.org](https://about.citiprogram.org)

2. **Obtain the CITI completion certificate.** This certificate proves that you have completed the required training.

3. **Create a PhysioNet account** at [https://physionet.org](https://physionet.org).

4. **Submit a data access request for MIMIC-IV** through the PhysioNet platform. You will be required to upload or attest to your CITI training certificate, agree to the PhysioNet Credentialed Health Data Use Agreement, and provide information about your intended use.

5. **Wait for access approval.** Processing time varies.

6. **Download the MIMIC-IV dataset** (specifically the `hosp/` module) after access is approved.

7. **Place the downloaded files** in the `hosp/` directory under the project root:
   ```
   CS Project/
   └── hosp/
       ├── patients.csv.gz
       ├── admissions.csv.gz
       ├── diagnoses_icd.csv.gz
       └── d_icd_diagnoses.csv.gz
   ```

8. **Run** `py data/preprocess_mimic.py` to encrypt and index the records.

Do not distribute, republish, or upload MIMIC-IV data to any public repository, even in processed or derived form. This is prohibited by the PhysioNet data use agreement.

**Official links:**
- CITI Program: [https://about.citiprogram.org](https://about.citiprogram.org)
- PhysioNet: [https://physionet.org](https://physionet.org)
- MIMIC-IV on PhysioNet: [https://physionet.org/content/mimiciv/](https://physionet.org/content/mimiciv/)

---

## 8. Running Without MIMIC-IV (Dummy Data)

Because MASE-SE's core purpose is to **demonstrate the cryptographic workflow**, it can be run with synthetic dummy data without any MIMIC-IV access.

The seed script (`database/seed.py`) creates all 20 users, 6 patients, and 54 consent policies. The search and authorization workflow, the consent revocation demonstration, and all cryptographic benchmarks work on these seeded actors alone.

If you run `py app.py` after seeding but before running the MIMIC preprocessor, the dashboard will load with:
- 0 EHR records (the cloud records table is empty)
- Full consent management working
- Authorization checks working (no records to return, but decisions are made)
- All API endpoints functional

For a meaningful search demonstration without MIMIC-IV, you can insert a small synthetic EHR record manually. See `MANUAL.txt` for step-by-step instructions on creating a synthetic test record.

The dummy data fields that the pipeline expects for a minimal EHR record:

```
patient_id   — links to system_patients (e.g., "PATIENT_001")
hospital_id  — "Hospital_A", "Hospital_B", or "Hospital_C"
plaintext    — any text string (the EHR content to encrypt)
keywords     — list of terms to index (e.g., ["diabetes", "hypertension"])
```

The dummy dataset is provided only to demonstrate the cryptographic workflow. It is not a substitute for the MIMIC-IV dataset and should not be interpreted as representing real clinical scenarios.

---

## 9. Repository Structure

```
CS Project/
│
├── README.md                        This file
├── MANUAL.txt                       Step-by-step user manual
├── requirements.txt                 Python dependencies
├── run.bat                          Windows one-click launcher
├── app.py                           Flask application — main entry point
│
├── config/
│   ├── __init__.py
│   └── settings.py                  All paths, constants, and configuration
│
├── crypto/                          All cryptographic primitives
│   ├── __init__.py
│   ├── hashing.py                   SHA-256 identity protection
│   ├── ehr_encryption.py            AES-256-GCM encrypt and decrypt
│   ├── searchable_encryption.py     HMAC-SHA256 search token generation
│   └── key_manager.py               Per-hospital key loading + MPC stubs
│
├── database/
│   ├── __init__.py
│   ├── db.py                        SQLite schema (7 tables) + query helpers
│   ├── seed.py                      One-time setup: keys, users, consent
│   └── mase_se.db                   SQLite database file (created at runtime)
│
├── services/                        Business logic layer
│   ├── __init__.py
│   ├── audit_service.py             Append/read audit log events
│   ├── consent_service.py           Grant and revoke consent policies
│   ├── authorization_service.py     4-condition access decision engine
│   ├── search_service.py            HMAC search over protected index
│   └── ehr_service.py               Cloud view + authorized decryption
│
├── data/
│   ├── __init__.py
│   └── preprocess_mimic.py          MIMIC-IV loader, encryptor, indexer
│
├── models/
│   └── __init__.py                  Reserved for future data model classes
│
├── templates/
│   └── index.html                   Dashboard HTML (single-page application)
│
├── static/
│   ├── css/
│   │   └── style.css                Professional dashboard CSS
│   └── js/
│       └── app.js                   Vanilla JavaScript SPA logic
│
├── tests/
│   ├── __init__.py
│   ├── test_system.py               19 automated unit tests
│   └── smoke_test.py                36 end-to-end API tests (requires running server)
│
└── hosp/                            MIMIC-IV data directory (NOT in repository)
    ├── patients.csv.gz              (must be obtained from PhysioNet)
    ├── admissions.csv.gz
    ├── diagnoses_icd.csv.gz
    └── d_icd_diagnoses.csv.gz
```

---

## 10. Installation

### Requirements

- **Python 3.10 or later** (tested on Python 3.12)
- **Operating system:** Windows (developed and tested on Windows 10/11 with PowerShell). Linux and macOS should work with minor command adjustments (`python3` instead of `py`, `/` path separators).
- **Internet:** Not required at runtime. Required once to download dependencies via pip.

### Step 1 — Clone the repository

```bash
git clone https://github.com/<your-username>/<your-repository>.git
cd "CS Project"
```

### Step 2 — Create a virtual environment

**Windows (PowerShell):**
```powershell
py -m venv .venv
.venv\Scripts\activate
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

The `requirements.txt` file specifies:
```
flask==3.0.3
pycryptodome==3.20.0
pandas==2.2.0
numpy==1.26.0
```

- **Flask**: Web framework serving the dashboard and REST API.
- **PyCryptodome**: Provides AES-256-GCM and random byte generation (`Crypto.Cipher.AES`, `Crypto.Random`).
- **Pandas**: CSV file loading and merging for MIMIC-IV preprocessing.
- **NumPy**: Numerical support for Pandas.

### Step 4 — Configure paths (optional)

All configuration is in `config/settings.py`. The defaults work correctly when the project is run from its own directory:

```python
DATABASE_PATH  = "database/mase_se.db"     # SQLite database
MIMIC_DATA_DIR = "hosp/"                    # MIMIC-IV CSV files
MAX_RECORDS    = 10_000                     # Records to import
HOSPITALS      = ["Hospital_A", "Hospital_B", "Hospital_C"]
ROLES          = ["Doctor", "Nurse", "Researcher", "Patient"]
```

If your MIMIC-IV files are in a different directory, edit `MIMIC_DATA_DIR` before running the preprocessor.

> **Note on `FLASK_SECRET_KEY`**: The current value is a fixed demo string. Do not use this value in any internet-accessible deployment. Replace it with a strong random secret and store it as an environment variable.

---

## 11. Quick Start

```bash
# 1. Clone and enter the project directory
git clone https://github.com/<your-username>/<your-repository>.git
cd "CS Project"

# 2. Create and activate virtual environment (Windows)
py -m venv .venv
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Seed the database (creates users, keys, consent policies)
py database/seed.py

# 5. (Optional but recommended) Import MIMIC-IV data
#    — Requires the four .csv.gz files in hosp/
#    — Takes approximately 90 seconds
py data/preprocess_mimic.py

# 6. Run the application
py app.py

# 7. Open your browser
#    http://localhost:5000
```

After step 4 (with or without step 5), the application is fully operational for demonstrating the authorization and consent workflow. Step 5 populates the database with 10,000 encrypted EHR records and 343,000+ HMAC search index entries.

---

## 12. Example Workflow

### Input

A doctor (`DOCTOR_001`, role: Doctor, hospital: Hospital_A) searches for keyword `"diabetes"` in patient `PATIENT_001`'s records.

Patient `PATIENT_001`'s consent grants Hospital_A / Doctor access.

### Cryptographic Processing

**Step 1 — Identity protection (SHA-256):**
```
"PATIENT_001" → SHA-256 → "a3f2b8c1d4e5f60789abc..." (64 hex chars)
```
This hash is what the cloud uses to look up the patient's records.

**Step 2 — Search token generation (HMAC-SHA256):**
```
keyword: "diabetes"
key:     Hospital_A.search_key (32 random bytes, generated at setup)
token:   HMAC-SHA256(search_key, "diabetes") = "8f2a1c3d7b9e4f6a..." (64 hex chars)
```
The cloud receives `8f2a1c3d7b9e4f6a...` — it never sees the word "diabetes".

**Step 3 — Authorization decision:**
```
Hospital Match:  Hospital_A ∈ PATIENT_001's granted hospitals  → ✓
Role Match:      Doctor     ∈ PATIENT_001's granted roles      → ✓
Consent Active:  access_granted=1, status='ACTIVE'             → ✓
Time Valid:      valid_until IS NULL (no expiry)               → ✓
Result: ACCESS GRANTED
```

**Step 4 — EHR decryption (AES-256-GCM):**
```
ciphertext + nonce + tag → AES-256-GCM(Hospital_A.ehr_key) → plaintext EHR

Output:
MIMIC-IV EHR Record
Patient ID  : P10006
Admission   : 29079034
Admit Date  : 2140-01-03
Discharge   : 2140-01-05
Age         : 53
Gender      : M
Admission Type: ELECTIVE

Diagnoses:
  [E11.9] Type 2 diabetes mellitus without complications
  [I10]   Essential (primary) hypertension
```

**Step 5 — Audit entry:**
```
SEARCH_REQUEST  | DOCTOR_001 | keywords=['diabetes'] | success
AUTH_GRANTED    | DOCTOR_001 | PATIENT_001 hash      | All conditions satisfied
EHR_DECRYPTED   | DOCTOR_001 | REC_00040             | success
```

### After Consent Revocation

Patient revokes Hospital_A / Doctor:
```
Database: consent_policies  →  access_granted=0, status='REVOKED'
```

Same search by DOCTOR_001:
```
Hospital Match:  ✓  (doctor's hospital unchanged)
Role Match:      ✓  (doctor's role unchanged)
Consent Active:  ✗  (consent is now REVOKED)
Time Valid:      ✓
Result: ACCESS DENIED — "Patient consent has been revoked or is inactive."
```

No decryption occurs. The ciphertext is never accessed.

---

## 13. Reproducing the Project

### Option A — Without MIMIC-IV (Recommended First Test)

No dataset access required. The cryptographic workflow and authorization demonstration are fully functional.

```bash
py database/seed.py    # Creates DB, keys, users, consent
py app.py              # Start dashboard at http://localhost:5000
```

Run the automated tests:
```bash
py tests/test_system.py    # 19 unit tests
```

### Option B — With MIMIC-IV (Full Dataset)

Requires authorized access through PhysioNet (see [Section 7](#7-dataset--mimic-iv)).

After obtaining access and downloading the four required files:

```bash
# Place files in hosp/
# patients.csv.gz, admissions.csv.gz, diagnoses_icd.csv.gz, d_icd_diagnoses.csv.gz

py database/seed.py              # Seed users and keys (skip if already done)
py data/preprocess_mimic.py      # Encrypt 10,000 records (~90 seconds)
py app.py                        # Start dashboard
```

The dashboard Overview page will show:
- 10,000 encrypted EHR records distributed across three hospitals
- 343,000+ HMAC search index entries
- All consent policies active

---

## 14. Limitations

| Limitation | Detail |
|------------|--------|
| **Prototype, not production** | Keys are stored in an SQLite file on disk. A production system requires hardware security modules (HSM) or a managed key management service (KMS). |
| **No threshold key distribution** | MPC/Shamir secret sharing is not implemented. A single key per hospital is used. |
| **MIMIC-IV access required** | Reproducing the full experiment requires completing the PhysioNet access process. |
| **SQLite concurrency** | SQLite is appropriate for a local demonstration but not for a multi-user clinical environment. |
| **No TLS** | Flask runs on HTTP. Any real deployment would require HTTPS. |
| **Fixed FLASK_SECRET_KEY** | The value in `config/settings.py` is a demo string and must be replaced before any internet-facing use. |
| **Simple SSE scheme** | The HMAC-SHA256 keyword search does not support fuzzy matching, substring search, or ranked results. |
| **Consent revocation is forward-only** | Revoking consent prevents future access but does not retroactively erase records that were previously delivered in plaintext. |
| **Simulated users** | The 20 users are synthetic. There is no real authentication system (no passwords, no session tokens). The demo selects a user from a dropdown. |
| **MIMIC-IV hospital assignment is artificial** | The three-hospital partition (`subject_id % 3`) is a simulation convenience; MIMIC-IV is sourced from a single real institution. |

---

## 15. Future Improvements

The following are technically motivated directions for extending this prototype. They are **not implemented** in the current codebase.

| Extension | Description |
|-----------|-------------|
| **MPC / Shamir (2-of-3) key sharing** | Replace per-hospital AES key with three Shamir shares; require 2-of-3 authorities for key reconstruction. Placeholder interfaces already exist in `key_manager.py`. |
| **Hidden access policy** | Encode authorization attributes inside the ciphertext (CP-ABE) so the cloud cannot determine which roles the policy applies to. |
| **Time-bound delegation tokens** | Allow a physician to delegate time-limited access to another provider via HMAC-based tokens. |
| **Verifiable search results** | Use an HMAC accumulator scheme to let the client verify that the cloud returned all matching records and did not omit any. |
| **Real user authentication** | Replace the dropdown user selector with password-based login, session tokens, and role-based access control at the HTTP layer. |
| **HTTPS / TLS** | Configure the Flask server with TLS certificates for encrypted transport. |
| **Formal security evaluation** | Conduct a formal security analysis under the UC (Universal Composability) or game-based security model for the SSE scheme. |
| **Performance scaling** | Benchmark on larger MIMIC-IV subsets (100,000+ records) and evaluate index lookup time, encryption throughput, and memory usage. |
| **Differential privacy for search** | Add controlled noise to search result counts to prevent inference of record counts from repeated queries. |

---

## 16. Disclaimer

MASE-SE is an academic research prototype developed for a university Computer Science research project. It is designed to demonstrate cryptographic concepts in a realistic clinical data context.

**This system is not a production healthcare security solution.** It has not been audited by a security professional, has not been evaluated for compliance with HIPAA, GDPR, HL7 FHIR security requirements, or any other healthcare data regulation, and should not be deployed in any real clinical environment without extensive further development, security review, and legal compliance assessment.

The use of MIMIC-IV data in this project is governed by the PhysioNet Credentialed Health Data Use Agreement. Users who obtain MIMIC-IV access are solely responsible for complying with the terms of that agreement.

---

## 17. Attribution and Dataset Citation

### MIMIC-IV Dataset

If you use MIMIC-IV in your research or reproduction of this project, you must cite the dataset according to PhysioNet's current citation requirements. The standard citations are:

> Johnson, A., Bulgarelli, L., Pollard, T., Horng, S., Celi, L. A., & Mark, R. (2023). **MIMIC-IV** (version 2.2). PhysioNet. https://doi.org/10.13026/6mm1-ek67

> Goldberger, A., Amaral, L., Glass, L., Hausdorff, J., Ivanov, P. C., Mark, R., ... & Stanley, H. E. (2000). **PhysioBank, PhysioToolkit, and PhysioNet: Components of a new research resource for complex physiologic signals.** Circulation [Online]. 101 (23), pp. e215–e220.

Always consult the current PhysioNet citation page at [https://physionet.org/content/mimiciv/](https://physionet.org/content/mimiciv/) for the most up-to-date citation format.

### Cryptographic Library

This project uses [PyCryptodome](https://pycryptodome.readthedocs.io/) for AES-256-GCM and cryptographically secure random byte generation. PyCryptodome is released under the BSD 2-Clause License.

### License

This repository does not currently include a license file. If you intend to publish or reuse this code, contact the project author before doing so.
