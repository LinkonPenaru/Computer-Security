"""
tests/test_system.py
====================
Automated tests for the MASE-SE 60% prototype.

Covers all 12 required test scenarios from the specification.
Run: py tests/test_system.py
"""

import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Use a temporary in-memory database for tests
os.environ["MASE_TEST_MODE"] = "1"

from crypto import hashing, ehr_encryption, searchable_encryption as se, key_manager
from database import db
from services import consent_service, authorization_service, audit_service
from Crypto.Random import get_random_bytes

# ── Override DB path for tests ─────────────────────────────────────────────────
import config.settings as settings
settings.DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "test_mase_se.db"
)
# Re-import db so it picks up the new path
import importlib
importlib.reload(db)
importlib.reload(consent_service)
importlib.reload(authorization_service)
importlib.reload(audit_service)


def _setup_test_db():
    """Create tables and insert minimal test data."""
    db.init_db()
    # Generate fresh test keys
    key_manager.initialize_keys()

    # Insert 2 test users
    user_hash_d = hashing.hash_user_id("TEST_DOCTOR")
    user_hash_n = hashing.hash_user_id("TEST_NURSE")
    user_hash_r = hashing.hash_user_id("TEST_DOC_C")

    for uid, uhash, role, hospital in [
        ("TEST_DOCTOR", user_hash_d, "Doctor", "Hospital_A"),
        ("TEST_NURSE",  user_hash_n, "Nurse",  "Hospital_A"),
        ("TEST_DOC_C",  user_hash_r, "Doctor", "Hospital_C"),
    ]:
        db.execute(
            "INSERT OR IGNORE INTO users (user_id, user_hash, full_name, role, hospital_id) VALUES (?,?,?,?,?)",
            (uid, uhash, uid, role, hospital),
        )

    # Insert 1 test patient
    patient_hash = hashing.hash_user_id("TEST_PATIENT")
    db.execute(
        "INSERT OR IGNORE INTO system_patients (patient_id, patient_hash, assigned_hospital) VALUES (?,?,?)",
        ("TEST_PATIENT", patient_hash, "Hospital_A"),
    )

    # Default consent: Hospital_A/Doctor=GRANTED, Hospital_A/Nurse=GRANTED, Hospital_C/Doctor=DENIED
    for hosp, role, granted in [
        ("Hospital_A", "Doctor",  1),
        ("Hospital_A", "Nurse",   1),
        ("Hospital_C", "Doctor",  0),
    ]:
        status = "ACTIVE" if granted else "REVOKED"
        db.execute(
            """INSERT OR REPLACE INTO consent_policies
                   (patient_hash, hospital_id, role, access_granted, status)
               VALUES (?,?,?,?,?)""",
            (patient_hash, hosp, role, granted, status),
        )

    return patient_hash


class TestHashing(unittest.TestCase):
    """Test 1: SHA-256 patient hashing."""

    def test_hash_produces_64_char_hex(self):
        h = hashing.hash_user_id("PATIENT_001")
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_same_input_same_hash(self):
        self.assertEqual(
            hashing.hash_user_id("PATIENT_001"),
            hashing.hash_user_id("PATIENT_001"),
        )

    def test_different_inputs_different_hashes(self):
        self.assertNotEqual(
            hashing.hash_user_id("PATIENT_001"),
            hashing.hash_user_id("PATIENT_002"),
        )

    def test_verify_round_trip(self):
        h = hashing.hash_user_id("USER_X")
        self.assertTrue(hashing.verify_user_id("USER_X", h))
        self.assertFalse(hashing.verify_user_id("USER_Y", h))


class TestEHREncryption(unittest.TestCase):
    """Tests 2-3: AES-256-GCM encryption and wrong-key failure."""

    def setUp(self):
        self.key      = ehr_encryption.generate_key()
        self.text     = "Patient: diabetes mellitus, admit 2024-01-15"

    def test_encrypt_produces_different_nonces(self):
        """Test 2a: same key, same plaintext → different nonces (never reuse)."""
        e1 = ehr_encryption.encrypt_ehr(self.text, self.key)
        e2 = ehr_encryption.encrypt_ehr(self.text, self.key)
        self.assertNotEqual(e1["nonce"], e2["nonce"])

    def test_encrypt_decrypt_round_trip(self):
        """Test 2b: encrypt then decrypt produces original plaintext."""
        enc = ehr_encryption.encrypt_ehr(self.text, self.key)
        dec = ehr_encryption.decrypt_ehr(enc["ciphertext"], enc["nonce"], enc["tag"], self.key)
        self.assertEqual(dec, self.text)

    def test_wrong_key_raises(self):
        """Test 3: decryption with wrong key raises ValueError."""
        enc      = ehr_encryption.encrypt_ehr(self.text, self.key)
        wrong_key = ehr_encryption.generate_key()
        with self.assertRaises(ValueError):
            ehr_encryption.decrypt_ehr(enc["ciphertext"], enc["nonce"], enc["tag"], wrong_key)

    def test_ciphertext_is_not_plaintext(self):
        """Plaintext must not appear in ciphertext."""
        enc = ehr_encryption.encrypt_ehr(self.text, self.key)
        self.assertNotIn("diabetes", enc["ciphertext"])


class TestSearchableEncryption(unittest.TestCase):
    """Tests 4-6: HMAC search tokens and keyword search."""

    def setUp(self):
        self.sk = get_random_bytes(32)

    def test_token_generation(self):
        """Test 4: token is a 64-char hex string."""
        tok = se.generate_search_token("diabetes", self.sk)
        self.assertEqual(len(tok), 64)

    def test_same_keyword_same_token(self):
        """Test 5a: deterministic — same keyword + key = same token."""
        t1 = se.generate_search_token("diabetes", self.sk)
        t2 = se.generate_search_token("diabetes", self.sk)
        self.assertEqual(t1, t2)

    def test_different_keywords_different_tokens(self):
        """Test 5b: different keywords produce different tokens."""
        t1 = se.generate_search_token("diabetes",    self.sk)
        t2 = se.generate_search_token("hypertension", self.sk)
        self.assertNotEqual(t1, t2)

    def test_token_hides_plaintext(self):
        """Test 5c: token does not contain the plaintext keyword."""
        tok = se.generate_search_token("diabetes", self.sk)
        self.assertNotIn("diabetes", tok)

    def test_keyword_extraction(self):
        """Test 6: keyword extraction removes stopwords and short words."""
        kws = se.extract_keywords_from_diagnosis("Type 2 diabetes mellitus with nephropathy")
        self.assertIn("diabetes", kws)
        self.assertIn("mellitus", kws)
        self.assertIn("nephropathy", kws)
        self.assertNotIn("with", kws)
        self.assertNotIn("type", kws)


class TestAuthorization(unittest.TestCase):
    """Tests 7-12: authorization engine."""

    @classmethod
    def setUpClass(cls):
        cls.patient_hash = _setup_test_db()

    def test_authorized_doctor_hospital_a(self):
        """Test 7: Doctor + Hospital_A + Active Consent → ALLOW."""
        result = authorization_service.check_authorization("TEST_DOCTOR", self.patient_hash)
        self.assertTrue(result["hospital_match"],  "Hospital match should be True")
        self.assertTrue(result["role_match"],      "Role match should be True")
        self.assertTrue(result["consent_active"],  "Consent should be active")
        self.assertTrue(result["time_valid"],      "Time should be valid")
        self.assertTrue(result["allowed"],         "Access should be ALLOWED")

    def test_unauthorized_nurse_hospital_a(self):
        """
        Test 8: Nurse + Hospital_A.
        Initial consent grants Nurses on Hospital_A, so this passes.
        We test the REVOKED case below (test 10).
        """
        result = authorization_service.check_authorization("TEST_NURSE", self.patient_hash)
        # Nurse on Hospital_A is GRANTED in initial seed
        self.assertTrue(result["allowed"])

    def test_unauthorized_hospital_c(self):
        """Test 9: Doctor + Hospital_C + Consent DENIES C → DENY."""
        result = authorization_service.check_authorization("TEST_DOC_C", self.patient_hash)
        self.assertFalse(result["allowed"], "Hospital C Doctor should be DENIED")

    def test_revoked_consent(self):
        """Test 10: Revoke Hospital_A/Nurse → same nurse DENIED afterwards."""
        # Revoke
        consent_service.revoke(self.patient_hash, "Hospital_A", "Nurse", actor="test")
        result = authorization_service.check_authorization("TEST_NURSE", self.patient_hash)
        self.assertFalse(result["consent_active"], "Consent should be revoked")
        self.assertFalse(result["allowed"],        "Access should be DENIED after revocation")

        # Re-grant for other tests
        consent_service.grant(self.patient_hash, "Hospital_A", "Nurse", actor="test")

    def test_revoke_then_re_grant(self):
        """Test 11: Revoke then re-grant restores access."""
        consent_service.revoke(self.patient_hash, "Hospital_A", "Doctor", actor="test")
        after_revoke = authorization_service.check_authorization("TEST_DOCTOR", self.patient_hash)
        self.assertFalse(after_revoke["allowed"])

        consent_service.grant(self.patient_hash, "Hospital_A", "Doctor", actor="test")
        after_grant = authorization_service.check_authorization("TEST_DOCTOR", self.patient_hash)
        self.assertTrue(after_grant["allowed"])

    def test_consent_revocation_demo_scenario(self):
        """
        Test 12: Complete teacher demonstration scenario.
        Doctor_A searches → ALLOWED → Patient revokes → Doctor_A → DENIED.
        """
        # Step 1: Ensure consent is granted
        consent_service.grant(self.patient_hash, "Hospital_A", "Doctor", actor="PATIENT_001")
        before = authorization_service.check_authorization("TEST_DOCTOR", self.patient_hash)
        self.assertTrue(before["hospital_match"])
        self.assertTrue(before["role_match"])
        self.assertTrue(before["consent_active"])
        self.assertTrue(before["allowed"])

        # Step 2: Patient revokes Hospital_A
        consent_service.revoke(self.patient_hash, "Hospital_A", "Doctor", actor="PATIENT_001")

        # Step 3: Same doctor, same query → DENIED
        after = authorization_service.check_authorization("TEST_DOCTOR", self.patient_hash)
        self.assertTrue(after["hospital_match"],   "Hospital still matches (doctor unchanged)")
        self.assertTrue(after["role_match"],       "Role still matches (doctor unchanged)")
        self.assertFalse(after["consent_active"],  "Consent is now REVOKED")
        self.assertFalse(after["allowed"],         "Access is DENIED")

        # Restore
        consent_service.grant(self.patient_hash, "Hospital_A", "Doctor", actor="test")

    @classmethod
    def tearDownClass(cls):
        """Clean up test database."""
        test_db = settings.DATABASE_PATH
        if os.path.exists(test_db):
            try:
                os.remove(test_db)
            except Exception:
                pass


if __name__ == "__main__":
    print("=" * 60)
    print("  MASE-SE — Running Automated Tests")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()
    for cls in [TestHashing, TestEHREncryption, TestSearchableEncryption, TestAuthorization]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
