"""
app.py
======
MASE-SE — Flask application entry point.

Startup sequence:
  1. Initialise the database (create tables if missing).
  2. Load hospital cryptographic keys into memory.
  3. Register all API routes.
  4. Serve the single-page dashboard.

API endpoints
-------------
GET  /                                  → dashboard HTML
GET  /api/stats                         → system statistics
GET  /api/hospitals                     → hospital list + record counts
GET  /api/users                         → all 20 system users
GET  /api/patients                      → patient actors + consent summary
GET  /api/patients/<patient_id>/consent → full consent for one patient
POST /api/patients/<patient_id>/consent/grant   → grant access
POST /api/patients/<patient_id>/consent/revoke  → revoke access
GET  /api/cloud/<patient_id>            → cloud representation (NO plaintext)
POST /api/search                        → keyword search + authorization
POST /api/decrypt                       → decrypt a specific record (authorized only)
GET  /api/audit                         → recent audit log
GET  /api/performance                   → micro-benchmarks
"""

import sys, os, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, render_template, abort

# Core modules
from config.settings import FLASK_SECRET_KEY, DATABASE_PATH
from database import db
from crypto import key_manager, hashing
from services import (
    ehr_service,
    search_service,
    authorization_service,
    consent_service,
    audit_service,
    mpc_service,
    delegation_service,
)
from crypto import (
    shamir as shamir_crypto,
    delegation as delegation_crypto,
    policy_hiding,
    verifiable_search as vs,
)

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY


# ─── Startup ──────────────────────────────────────────────────────────────────

def _startup():
    """Initialise DB and load keys on first request."""
    db.init_db()
    stored = db.fetchall("SELECT * FROM hospital_keys")
    if stored:
        stored_keys = {r["hospital_id"]: {
            "ehr_key":    r["ehr_key_b64"],
            "search_key": r["search_key_b64"],
        } for r in stored}
        key_manager.initialize_keys(stored_keys)


with app.app_context():
    _startup()


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── /api/stats ───────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    keys_ready = key_manager.keys_initialized()
    ehr_stats  = ehr_service.get_stats()
    users      = db.fetchone("SELECT COUNT(*) c FROM users")["c"]
    patients   = db.fetchone("SELECT COUNT(*) c FROM system_patients")["c"]
    audit_cnt  = db.fetchone("SELECT COUNT(*) c FROM audit_log")["c"]

    return jsonify({
        "keys_initialized": keys_ready,
        "total_ehr_records": ehr_stats["total_records"],
        "index_entries":    ehr_stats["index_entries"],
        "by_hospital":      ehr_stats["by_hospital"],
        "total_users":      users,
        "total_patients":   patients,
        "audit_events":     audit_cnt,
    })


# ─── /api/hospitals ───────────────────────────────────────────────────────────

@app.route("/api/hospitals")
def api_hospitals():
    hospitals = ["Hospital_A", "Hospital_B", "Hospital_C"]
    result = []
    for h in hospitals:
        cnt = db.fetchone(
            "SELECT COUNT(*) c FROM ehr_records WHERE hospital_id=?", (h,)
        )
        result.append({
            "hospital_id":   h,
            "display_name":  h.replace("_", " "),
            "record_count":  cnt["c"] if cnt else 0,
            "keys_loaded":   h in key_manager._ehr_keys,
        })
    return jsonify(result)


# ─── /api/users ───────────────────────────────────────────────────────────────

@app.route("/api/users")
def api_users():
    users = db.fetchall("SELECT user_id, user_hash, full_name, role, hospital_id, status FROM users ORDER BY role, hospital_id")
    # Truncate hash for display
    for u in users:
        u["user_hash_preview"] = u["user_hash"][:16] + "…"
    return jsonify(users)


@app.route("/api/users/<user_id>")
def api_user_detail(user_id):
    user = db.fetchone("SELECT * FROM users WHERE user_id=?", (user_id,))
    if not user:
        return jsonify({"error": "User not found"}), 404
    user["user_hash_preview"] = user["user_hash"][:16] + "…"
    return jsonify(user)


# ─── /api/patients ────────────────────────────────────────────────────────────

@app.route("/api/patients")
def api_patients():
    patients = db.fetchall("SELECT * FROM system_patients ORDER BY patient_id")
    result = []
    for p in patients:
        consent = consent_service.get_consent_summary(p["patient_hash"])
        rec_cnt = db.fetchone(
            "SELECT COUNT(*) c FROM ehr_records WHERE patient_hash=?",
            (p["patient_hash"],)
        )
        result.append({
            "patient_id":          p["patient_id"],
            "patient_hash":        p["patient_hash"],
            "patient_hash_preview": p["patient_hash"][:16] + "…",
            "assigned_hospital":   p["assigned_hospital"],
            "record_count":        rec_cnt["c"] if rec_cnt else 0,
            "consent_summary":     consent,
        })
    return jsonify(result)


@app.route("/api/patients/<patient_id>/consent")
def api_patient_consent(patient_id):
    patient_hash = hashing.hash_user_id(patient_id)
    policies = consent_service.get_all_policies(patient_hash)
    return jsonify({
        "patient_id":   patient_id,
        "patient_hash": patient_hash,
        "policies":     policies,
    })


@app.route("/api/patients/<patient_id>/consent/grant", methods=["POST"])
def api_grant(patient_id):
    data       = request.get_json(force=True) or {}
    hospital   = data.get("hospital_id")
    role       = data.get("role", "Doctor")
    valid_until = data.get("valid_until")
    actor      = data.get("actor", "system")

    if not hospital:
        return jsonify({"error": "hospital_id required"}), 400

    patient_hash = hashing.hash_user_id(patient_id)
    consent_service.grant(patient_hash, hospital, role, valid_until, actor)

    return jsonify({
        "status":      "granted",
        "patient_id":  patient_id,
        "hospital_id": hospital,
        "role":        role,
    })


@app.route("/api/patients/<patient_id>/consent/revoke", methods=["POST"])
def api_revoke(patient_id):
    data     = request.get_json(force=True) or {}
    hospital = data.get("hospital_id")
    role     = data.get("role", "Doctor")
    actor    = data.get("actor", "system")

    if not hospital:
        return jsonify({"error": "hospital_id required"}), 400

    patient_hash = hashing.hash_user_id(patient_id)
    consent_service.revoke(patient_hash, hospital, role, actor)

    return jsonify({
        "status":      "revoked",
        "patient_id":  patient_id,
        "hospital_id": hospital,
        "role":        role,
    })


# ─── /api/cloud ───────────────────────────────────────────────────────────────

@app.route("/api/cloud/<patient_id>")
def api_cloud(patient_id):
    """Return the cloud representation for a patient — NO plaintext EHR."""
    patient_hash = hashing.hash_user_id(patient_id)
    records = ehr_service.get_cloud_representation(patient_hash)
    return jsonify({
        "patient_id":   patient_id,
        "patient_hash": patient_hash,
        "records":      records,
        "note":         "Cloud view: no plaintext EHR content is stored or returned here.",
    })


# ─── /api/search ─────────────────────────────────────────────────────────────

@app.route("/api/search", methods=["POST"])
def api_search():
    """
    Full search + authorization workflow.

    Body: {user_id, keywords (str or list), patient_id (optional)}

    Returns:
      - search tokens (what the cloud receives)
      - matching record IDs
      - authorization decision (per condition)
      - decrypted EHR (only if authorized)
    """
    data       = request.get_json(force=True) or {}
    user_id    = data.get("user_id", "")
    patient_id = data.get("patient_id", "")
    raw_kw     = data.get("keywords", "")

    # Normalise keywords
    if isinstance(raw_kw, str):
        keywords = [k.strip() for k in raw_kw.split() if k.strip()]
    else:
        keywords = [k.strip() for k in raw_kw if k.strip()]

    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    if not keywords:
        return jsonify({"error": "keywords required"}), 400

    audit_service.log("SEARCH_REQUEST", user_id=user_id,
                      details=f"keywords={keywords}, patient={patient_id}")

    # 1. Search protected index
    search_result = search_service.search(user_id, keywords)

    # 2. If patient_id given, filter to that patient's records
    patient_hash = None
    if patient_id:
        patient_hash = hashing.hash_user_id(patient_id)
        all_ids = set(search_result["record_ids"])
        # Filter to records belonging to this patient
        if all_ids:
            placeholders = ",".join("?" * len(all_ids))
            patient_records = db.fetchall(
                f"SELECT record_id FROM ehr_records WHERE patient_hash=? AND record_id IN ({placeholders})",
                (patient_hash, *all_ids),
            )
            filtered_ids = [r["record_id"] for r in patient_records]
        else:
            filtered_ids = []
        search_result["record_ids"]    = filtered_ids
        search_result["record_count"]  = len(filtered_ids)

    # 3. Authorization check
    auth_result = None
    decrypted   = []
    if patient_id and patient_hash:
        auth_result = authorization_service.check_authorization(user_id, patient_hash)

        # 4. Decrypt first few records if authorized
        if auth_result["allowed"] and search_result["record_ids"]:
            for rid in search_result["record_ids"][:5]:   # show up to 5 results
                try:
                    dec = ehr_service.decrypt_record(rid, user_id)
                    decrypted.append(dec)
                except Exception as exc:
                    decrypted.append({"record_id": rid, "error": str(exc)})

    return jsonify({
        "search":        search_result,
        "authorization": auth_result,
        "decrypted_ehrs": decrypted,
    })


# ─── /api/decrypt ────────────────────────────────────────────────────────────

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """Decrypt a specific record after authorization check."""
    data       = request.get_json(force=True) or {}
    user_id    = data.get("user_id", "")
    record_id  = data.get("record_id", "")
    patient_id = data.get("patient_id", "")

    if not all([user_id, record_id, patient_id]):
        return jsonify({"error": "user_id, record_id, patient_id required"}), 400

    patient_hash = hashing.hash_user_id(patient_id)
    auth = authorization_service.check_authorization(user_id, patient_hash)

    if not auth["allowed"]:
        return jsonify({"allowed": False, "reason": auth["reason"], "authorization": auth}), 403

    try:
        dec = ehr_service.decrypt_record(record_id, user_id)
        return jsonify({"allowed": True, "authorization": auth, "ehr": dec})
    except Exception as exc:
        return jsonify({"allowed": True, "error": str(exc)}), 500


# ─── /api/audit ──────────────────────────────────────────────────────────────

@app.route("/api/audit")
def api_audit():
    limit  = int(request.args.get("limit", 100))
    events = audit_service.get_recent(limit)
    return jsonify(events)


# ─── /api/performance ────────────────────────────────────────────────────────

@app.route("/api/performance")
def api_performance():
    """
    Run micro-benchmarks and return real measured timings.
    All values are produced by actual program execution — never fabricated.
    """
    from crypto import ehr_encryption
    from Crypto.Random import get_random_bytes

    results = {}
    ITERATIONS = 20
    sample_text = "Patient EHR: diabetes mellitus type 2, hypertension, renal failure." * 5

    # EHR encryption benchmark
    key = ehr_encryption.generate_key()
    enc_times = []
    enc_result = None
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        enc_result = ehr_encryption.encrypt_ehr(sample_text, key)
        enc_times.append((time.perf_counter() - t0) * 1000)
    results["encrypt_avg_ms"] = round(sum(enc_times) / len(enc_times), 3)
    results["encrypt_min_ms"] = round(min(enc_times), 3)

    # EHR decryption benchmark
    dec_times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        ehr_encryption.decrypt_ehr(enc_result["ciphertext"], enc_result["nonce"], enc_result["tag"], key)
        dec_times.append((time.perf_counter() - t0) * 1000)
    results["decrypt_avg_ms"] = round(sum(dec_times) / len(dec_times), 3)

    # Search token generation benchmark
    from crypto import searchable_encryption as se
    sk = get_random_bytes(32)
    tok_times = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        se.generate_search_token("diabetes", sk)
        tok_times.append((time.perf_counter() - t0) * 1000)
    results["search_token_avg_ms"] = round(sum(tok_times) / len(tok_times), 4)

    # Auth check benchmark
    users = db.fetchall("SELECT user_id FROM users WHERE role='Doctor' LIMIT 1")
    pats  = db.fetchall("SELECT patient_hash FROM system_patients LIMIT 1")
    auth_times = []
    if users and pats:
        for _ in range(ITERATIONS):
            t0 = time.perf_counter()
            authorization_service.check_authorization(users[0]["user_id"], pats[0]["patient_hash"])
            auth_times.append((time.perf_counter() - t0) * 1000)
        results["auth_check_avg_ms"] = round(sum(auth_times) / len(auth_times), 3)

    # Storage overhead (sample)
    if enc_result:
        ct_bytes = len(enc_result["ciphertext"].encode())
        pt_bytes = len(sample_text.encode())
        results["storage_overhead_pct"] = round((ct_bytes / pt_bytes - 1) * 100, 1)
        results["plaintext_bytes"]      = pt_bytes
        results["ciphertext_bytes"]     = ct_bytes

    results["iterations"] = ITERATIONS
    return jsonify(results)


# ═══════════════════════════════════════════════════════════════════════════════
# 40% EXTENSION — Advanced Cryptographic Features
# ═══════════════════════════════════════════════════════════════════════════════

# ─── MPC — Shamir (2,3) Secret Sharing ─────────────────────────────────────

@app.route("/api/mpc/generate", methods=["POST"])
def api_mpc_generate():
    """
    Generate a new Shamir (2,3) MPC session.
    POST body: { "purpose": "key_derivation" }  (optional)
    """
    body    = request.get_json(silent=True) or {}
    purpose = body.get("purpose", "key_derivation")
    result  = mpc_service.generate_session(purpose=purpose)

    # Return shares with x-coord only (y_hex is partial secret — shown for demo)
    return jsonify({
        "session_id":  result["session_id"],
        "threshold":   result["threshold"],
        "n_shares":    result["n_shares"],
        "prime_hex":   result["prime_hex"],
        "secret_hash": result["secret_hash"],
        "shares": [
            {
                "hospital_id": s["hospital_id"],
                "x":           s["x"],
                "y_hex_short": s["y_hex"][:18] + "...",  # truncated for display
            }
            for s in result["shares"]
        ],
    })


@app.route("/api/mpc/reconstruct", methods=["POST"])
def api_mpc_reconstruct():
    """
    Attempt secret reconstruction from a subset of hospitals.
    POST body: { "session_id": "...", "hospitals": ["Hospital_A", "Hospital_B"] }
    """
    body = request.get_json(silent=True) or {}
    session_id = body.get("session_id", "")
    hospitals  = body.get("hospitals", [])

    if not session_id:
        return jsonify({"error": "session_id required"}), 400

    result = mpc_service.reconstruct_from_hospitals(session_id, hospitals)
    return jsonify(result)


@app.route("/api/mpc/sessions")
def api_mpc_sessions():
    """Return recent MPC sessions (metadata only)."""
    sessions = mpc_service.list_sessions(limit=10)
    return jsonify({"sessions": sessions})


# ─── Delegation — Time-Limited Tokens ──────────────────────────────────────

@app.route("/api/delegation/create", methods=["POST"])
def api_delegation_create():
    """
    Create a signed delegation token.
    POST body: {
        "delegator":         "DOCTOR_001",
        "delegatee":         "DOCTOR_002",
        "patient_id":        "PATIENT_001",
        "hospital_id":       "Hospital_A",
        "role":              "Doctor",
        "duration_minutes":  5,
        "scope":             "search"
    }
    """
    body = request.get_json(silent=True) or {}
    required = ["delegator", "delegatee", "patient_id", "hospital_id", "role"]
    missing  = [f for f in required if not body.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    result = delegation_service.create_token(
        delegator        = body["delegator"],
        delegatee        = body["delegatee"],
        patient_id       = body["patient_id"],
        hospital_id      = body["hospital_id"],
        role             = body["role"],
        duration_minutes = int(body.get("duration_minutes", 60)),
        scope            = body.get("scope", "search"),
    )

    if "error" in result:
        return jsonify(result), 403

    return jsonify({
        "token_id":     result["token_id"],
        "delegator":    result["payload"]["delegator"],
        "delegatee":    result["payload"]["delegatee"],
        "patient_id":   result["payload"]["patient_id"],
        "hospital_id":  result["payload"]["hospital_id"],
        "role":         result["payload"]["role"],
        "scope":        result["payload"]["scope"],
        "issued_at":    result["payload"]["issued_at"],
        "expires_at":   result["expires_at"],
        "signature":    result["signature"],
        "stored":       result["stored"],
    })


@app.route("/api/delegation/validate", methods=["POST"])
def api_delegation_validate():
    """
    Validate a delegation token for an access attempt.
    POST body: {
        "token_id":          "...",
        "requesting_user":   "DOCTOR_002",
        "patient_id":        "PATIENT_001",
        "operation":         "search"
    }
    """
    body = request.get_json(silent=True) or {}
    token_id        = body.get("token_id", "")
    requesting_user = body.get("requesting_user", "")
    patient_id      = body.get("patient_id", "")
    operation       = body.get("operation", "search")

    if not all([token_id, requesting_user, patient_id]):
        return jsonify({"error": "token_id, requesting_user, patient_id required"}), 400

    result = delegation_service.validate_token(token_id, requesting_user, patient_id, operation)
    return jsonify(result)


@app.route("/api/delegation/validate_expired", methods=["POST"])
def api_delegation_validate_expired():
    """
    Validate against a simulated-expired version of a token (teacher demo).
    POST body: { "token_id": "...", "requesting_user": "...", "patient_id": "..." }
    """
    body = request.get_json(silent=True) or {}
    token_id        = body.get("token_id", "")
    requesting_user = body.get("requesting_user", "")
    patient_id      = body.get("patient_id", "")

    expired_token = delegation_service.get_expired_demo_token(token_id)
    if not expired_token:
        return jsonify({"error": "Token not found"}), 404

    # Validate the expired version
    result = delegation_crypto.validate_token(expired_token, requesting_user, patient_id, "search")
    result["note"] = "This is a simulated-expiry demonstration. The token was artificially expired."
    return jsonify(result)


@app.route("/api/delegation/list")
def api_delegation_list():
    """List delegation tokens, optionally filtered."""
    patient_id = request.args.get("patient_id")
    delegatee  = request.args.get("delegatee")
    tokens     = delegation_service.list_tokens(patient_id=patient_id, delegatee=delegatee, limit=20)
    # Remove full_token_json from response (contains signature key material)
    safe = []
    for t in tokens:
        t.pop("full_token_json", None)
        safe.append(t)
    return jsonify({"tokens": safe})


# ─── Protected Policy (Hidden Access Policy) ───────────────────────────────

@app.route("/api/policy/<patient_id>")
def api_policy(patient_id):
    """
    Return logical and protected (cloud-side) policy representations for a patient.
    """
    from crypto.hashing import hash_user_id
    patient_hash = hash_user_id(patient_id)
    policies = consent_service.get_all_policies(patient_hash)

    protected = policy_hiding.build_patient_policy_summary(patient_id, [dict(p) for p in policies])

    return jsonify({
        "patient_id":        patient_id,
        "patient_hash":      patient_hash[:16] + "...",
        "total_policies":    len(protected),
        "protected_policies": protected,
        "disclaimer": (
            "Cloud view shows HMAC commitments, not plaintext attributes. "
            "This is a prototype policy-hiding mechanism — not formal CP-ABE."
        ),
    })


# ─── Verifiable Search ─────────────────────────────────────────────────────

@app.route("/api/verify", methods=["POST"])
def api_verify():
    """
    Compute or verify a search result set.
    POST body: {
        "keywords":    ["diabetes"],
        "record_ids":  ["REC_00040", ...],
        "expected_verification_value": "..."   (optional — if provided, verifies; else computes)
    }
    """
    body       = request.get_json(silent=True) or {}
    keywords   = body.get("keywords", [])
    record_ids = body.get("record_ids", [])
    expected   = body.get("expected_verification_value", None)

    if not keywords:
        return jsonify({"error": "keywords required"}), 400

    if expected:
        result = vs.verify_results(keywords, record_ids, expected)
    else:
        result = vs.compute_verification(keywords, record_ids)

    return jsonify(result)


# ─── Extended Performance (includes 40% features) ─────────────────────────

@app.route("/api/performance/advanced")
def api_performance_advanced():
    """
    Measure execution time for all cryptographic operations including 40% features.
    All measurements use actual execution — nothing is fabricated.
    """
    from Crypto.Random import get_random_bytes
    ITERS = 20
    results = {"iterations": ITERS, "measurements": {}}

    # 1. MPC share generation
    t0 = time.perf_counter()
    for _ in range(ITERS):
        shamir_crypto.generate_shares(get_random_bytes(15))
    results["measurements"]["mpc_share_generation_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 2. MPC reconstruction (2 shares)
    secret = get_random_bytes(15)
    gen    = shamir_crypto.generate_shares(secret)
    shares = gen["shares"][:2]
    t0 = time.perf_counter()
    for _ in range(ITERS):
        shamir_crypto.reconstruct_secret(shares)
    results["measurements"]["mpc_reconstruction_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 3. Delegation token generation
    from crypto.delegation import create_token as dt_create
    t0 = time.perf_counter()
    for _ in range(ITERS):
        tk = dt_create("DOCTOR_001", "DOCTOR_002", "PATIENT_001", "Hospital_A", "Doctor", 5)
    results["measurements"]["delegation_token_gen_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 4. Delegation token validation
    from crypto.delegation import validate_token as dt_validate
    sample_tk = dt_create("DOCTOR_001", "DOCTOR_002", "PATIENT_001", "Hospital_A", "Doctor", 5)
    full_tk   = sample_tk["full_token"]
    t0 = time.perf_counter()
    for _ in range(ITERS):
        dt_validate(full_tk, "DOCTOR_002", "PATIENT_001", "search")
    results["measurements"]["delegation_token_validate_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 5. Policy hiding — build protected policy
    t0 = time.perf_counter()
    for _ in range(ITERS):
        policy_hiding.build_protected_policy("PATIENT_001", "Hospital_A", "Doctor", "ACTIVE")
    results["measurements"]["policy_hiding_build_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 6. Policy hiding — match
    pp = policy_hiding.build_protected_policy("PATIENT_001", "Hospital_A", "Doctor", "ACTIVE")
    t0 = time.perf_counter()
    for _ in range(ITERS):
        policy_hiding.match_policy(pp, "Hospital_A", "Doctor", "ACTIVE", "PATIENT_001")
    results["measurements"]["policy_match_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 7. Verifiable search — compute
    sample_ids = [f"REC_{i:05d}" for i in range(50)]
    t0 = time.perf_counter()
    for _ in range(ITERS):
        vs.compute_verification(["diabetes"], sample_ids)
    results["measurements"]["verify_compute_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 8. Verifiable search — verify
    vval = vs.compute_verification(["diabetes"], sample_ids)["verification_value"]
    t0 = time.perf_counter()
    for _ in range(ITERS):
        vs.verify_results(["diabetes"], sample_ids, vval)
    results["measurements"]["verify_check_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 9. AES-256-GCM encryption (baseline reference)
    from crypto import ehr_encryption
    key = get_random_bytes(32)
    t0  = time.perf_counter()
    for _ in range(ITERS):
        ehr_encryption.encrypt_ehr("sample EHR text for benchmarking", key)
    results["measurements"]["aes_encrypt_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    # 10. HMAC search token generation (baseline reference)
    from crypto import searchable_encryption as se_mod
    sk = get_random_bytes(32)
    t0 = time.perf_counter()
    for _ in range(ITERS):
        se_mod.generate_search_token("diabetes", sk)
    results["measurements"]["hmac_token_gen_ms"] = round(
        (time.perf_counter() - t0) / ITERS * 1000, 4
    )

    results["unit"] = "milliseconds per operation (average over 20 iterations)"
    return jsonify(results)


# ─── __init__ helpers ─────────────────────────────────────────────────────────

@app.route("/api/setup/status")
def api_setup_status():
    """Check whether data has been loaded."""
    ehr_count  = db.fetchone("SELECT COUNT(*) c FROM ehr_records")["c"]
    user_count = db.fetchone("SELECT COUNT(*) c FROM users")["c"]
    keys_ok    = key_manager.keys_initialized()
    return jsonify({
        "ehr_records_loaded": ehr_count > 0,
        "users_seeded":       user_count > 0,
        "keys_initialized":   keys_ok,
        "ehr_count":          ehr_count,
        "user_count":         user_count,
        "ready":              ehr_count > 0 and user_count > 0 and keys_ok,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# DATA LOADER — Dummy / Custom Dataset Endpoints
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/api/dataloader/status")
def api_dataloader_status():
    """Return current DB data source and record counts."""
    ehr_count   = db.fetchone("SELECT COUNT(*) c FROM ehr_records")["c"]
    idx_count   = db.fetchone("SELECT COUNT(*) c FROM search_index")["c"]
    user_count  = db.fetchone("SELECT COUNT(*) c FROM users")["c"]

    # Detect data source by sampling record_ids
    source = "none"
    if ehr_count > 0:
        sample = db.fetchone("SELECT record_id FROM ehr_records LIMIT 1")
        if sample:
            rid = sample["record_id"]
            if rid.startswith("DUMMY_"):
                source = "dummy"
            elif rid.startswith("CUSTOM_") or rid.startswith("REC_CUSTOM"):
                source = "custom"
            else:
                source = "mimic"

    return jsonify({
        "ehr_records":   ehr_count,
        "search_index":  idx_count,
        "users":         user_count,
        "source":        source,
        "ready":         ehr_count > 0 and user_count > 0,
    })


@app.route("/api/dataloader/load-dummy", methods=["POST"])
def api_dataloader_load_dummy():
    """
    Load the built-in dummy dataset (500 fictional EHR records).
    No request body required.
    """
    try:
        from data.dummy_dataset import load_dummy_dataset
        result = load_dummy_dataset()
        return jsonify(result)
    except Exception as e:
        import traceback
        return jsonify({"success": False, "message": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/dataloader/load-custom", methods=["POST"])
def api_dataloader_load_custom():
    """
    Load a user-supplied CSV dataset.

    Accepts either:
      - multipart/form-data with file field "csv_file"
      - application/json with field "csv_content" (raw CSV string)
    """
    from data.custom_loader import load_custom_csv

    csv_content = None

    # Try JSON body first
    body = request.get_json(silent=True)
    if body and body.get("csv_content"):
        csv_content = body["csv_content"]

    # Try file upload
    if csv_content is None and "csv_file" in request.files:
        f = request.files["csv_file"]
        try:
            csv_content = f.read().decode("utf-8")
        except UnicodeDecodeError:
            return jsonify({"success": False, "message": "File must be UTF-8 encoded."}), 400

    if not csv_content:
        return jsonify({"success": False, "message": "No CSV data provided. "
                        "Send JSON {\"csv_content\": \"...\"} or multipart file 'csv_file'."}), 400

    try:
        result = load_custom_csv(csv_content, is_content=True)
        status_code = 200 if result["success"] else 422
        return jsonify(result), status_code
    except Exception as e:
        import traceback
        return jsonify({"success": False, "message": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/dataloader/template")
def api_dataloader_template():
    """Download the CSV template file."""
    from data.custom_loader import get_template_csv
    content = get_template_csv()
    return app.response_class(
        response=content,
        status=200,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=MASE_SE_CUSTOM_DATASET_TEMPLATE.csv"}
    )


# ─── __init__ helpers ─────────────────────────────────────────────────────────


if __name__ == "__main__":
    print("=" * 60)
    print("  MASE-SE — Multi-Authority Searchable Encryption Demo")
    print("=" * 60)
    print(f"  Database : {DATABASE_PATH}")
    print(f"  URL      : http://localhost:5000")
    print()
    app.run(debug=True, port=5000, use_reloader=False)

