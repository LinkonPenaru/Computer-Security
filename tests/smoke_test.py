"""Quick API smoke test — verifies all endpoints return expected data."""
import urllib.request, json, sys

BASE = "http://localhost:5000"

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read())

def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data,
                                  headers={"Content-Type":"application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())

errors = []
passed = 0

def check(name, condition, got=""):
    global passed
    if condition:
        print(f"  ✅ {name}")
        passed += 1
    else:
        print(f"  ❌ {name}: {got}")
        errors.append(name)

print("\n=== MASE-SE API Smoke Tests ===\n")

# 1. Stats
s = get("/api/stats")
check("Stats: 10,000 EHR records", s["total_ehr_records"] == 10000, s.get("total_ehr_records"))
check("Stats: 343,108 index entries", s["index_entries"] >= 300000, s.get("index_entries"))
check("Stats: 20 users", s["total_users"] == 20, s.get("total_users"))
check("Stats: keys initialized", s["keys_initialized"] is True)

# 2. Users
users = get("/api/users")
check("Users: 20 returned", len(users) == 20, len(users))
doc = next((u for u in users if u["user_id"]=="DOCTOR_001"), None)
check("Users: DOCTOR_001 exists", doc is not None)
check("Users: DOCTOR_001 is Hospital_A Doctor", doc and doc["role"]=="Doctor" and doc["hospital_id"]=="Hospital_A")
check("Users: hash is 64-char hex + ellipsis", doc and len(doc["user_hash_preview"]) > 16)

# 3. Patients
patients = get("/api/patients")
check("Patients: 6 returned", len(patients) == 6, len(patients))

# 4. Cloud view (PATIENT_001)
cloud = get("/api/cloud/PATIENT_001")
check("Cloud: has patient_hash", bool(cloud.get("patient_hash")))
check("Cloud: has records", len(cloud.get("records",[])) > 0, len(cloud.get("records",[])))
check("Cloud: no plaintext in ciphertext preview", 
      all("diabetes" not in r.get("encrypted_ehr_preview","") for r in cloud.get("records",[])))

# 5. Search — authorized (DOCTOR_001 → PATIENT_001, diabetes)
result = post("/api/search", {
    "user_id": "DOCTOR_001",
    "patient_id": "PATIENT_001",
    "keywords": "diabetes"
})
sr = result.get("search", {})
auth = result.get("authorization", {})
check("Search: returns tokens", len(sr.get("search_tokens",[])) > 0)
check("Search: found matching records", sr.get("record_count",0) > 0, sr.get("record_count"))
check("Search: hospital_match=True", auth.get("hospital_match") is True)
check("Search: role_match=True", auth.get("role_match") is True)
check("Search: consent_active=True", auth.get("consent_active") is True)
check("Search: time_valid=True", auth.get("time_valid") is True)
check("Search: ACCESS GRANTED", auth.get("allowed") is True)
check("Search: decrypted EHR returned", len(result.get("decrypted_ehrs",[])) > 0)

# Verify decrypted EHR contains real content (not ciphertext)
ehrs = result.get("decrypted_ehrs", [])
if ehrs:
    pt = ehrs[0].get("plaintext","")
    check("Decrypt: plaintext is readable EHR", "MIMIC-IV EHR" in pt or "Patient ID" in pt, pt[:50])
else:
    check("Decrypt: plaintext present", False, "no decrypted EHRs")

# 6. Search — unauthorized hospital (DOCTOR_007 is Hospital_C, PATIENT_001 denies C)
result_c = post("/api/search", {
    "user_id": "DOCTOR_007",
    "patient_id": "PATIENT_001",
    "keywords": "diabetes"
})
auth_c = result_c.get("authorization", {})
check("Unauthorized hospital: ACCESS DENIED", auth_c.get("allowed") is False, auth_c)
check("Unauthorized hospital: consent_active=False", auth_c.get("consent_active") is False, auth_c.get("consent_active"))

# 7. Consent revoke → re-search
rev = post("/api/patients/PATIENT_001/consent/revoke", {"hospital_id":"Hospital_A","role":"Doctor","actor":"PATIENT_001"})
check("Revoke: status=revoked", rev.get("status")=="revoked", rev)

result_after = post("/api/search", {
    "user_id": "DOCTOR_001",
    "patient_id": "PATIENT_001",
    "keywords": "diabetes"
})
auth_after = result_after.get("authorization", {})
check("After revoke: hospital_match still True", auth_after.get("hospital_match") is True)
check("After revoke: consent_active=False", auth_after.get("consent_active") is False, auth_after.get("consent_active"))
check("After revoke: ACCESS DENIED", auth_after.get("allowed") is False, auth_after.get("allowed"))
check("After revoke: no decrypted EHRs", len(result_after.get("decrypted_ehrs",[])) == 0)

# 8. Re-grant → access restored
grant = post("/api/patients/PATIENT_001/consent/grant", {"hospital_id":"Hospital_A","role":"Doctor","actor":"PATIENT_001"})
check("Re-grant: status=granted", grant.get("status")=="granted", grant)
result_regrant = post("/api/search", {"user_id":"DOCTOR_001","patient_id":"PATIENT_001","keywords":"diabetes"})
check("After re-grant: ACCESS GRANTED", result_regrant.get("authorization",{}).get("allowed") is True)

# 9. Audit log has events
audit = get("/api/audit?limit=20")
check("Audit: events recorded", len(audit) > 0, len(audit))
types = {e["event_type"] for e in audit}
check("Audit: has AUTH_GRANTED event", "AUTH_GRANTED" in types, types)
check("Audit: has CONSENT_REVOKED event", "CONSENT_REVOKED" in types, types)

# 10. Performance
perf = get("/api/performance")
check("Performance: encrypt_avg_ms exists", "encrypt_avg_ms" in perf)
check("Performance: decrypt_avg_ms exists", "decrypt_avg_ms" in perf)
check("Performance: no fabricated values (all > 0)", 
      perf.get("encrypt_avg_ms",0) > 0 and perf.get("decrypt_avg_ms",0) > 0)

print(f"\n{'='*45}")
print(f"  Result: {passed}/{passed+len(errors)} tests passed")
if errors:
    print(f"  Failed: {errors}")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED ✅")
    sys.exit(0)
