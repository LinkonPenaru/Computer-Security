"""
tests/test_advanced.py
======================
Automated tests for the 40% extension features of MASE-SE.

Tests cover:
  - Shamir (2,3) MPC secret sharing
  - HMAC-SHA256 delegation tokens
  - Prototype policy hiding
  - HMAC-based verifiable search
  - Integration (consent revocation overrides delegation)

Run with:
    py tests/test_advanced.py
"""

import sys, os, time, json, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Random import get_random_bytes


# ─── MPC / Shamir (2,3) Tests ─────────────────────────────────────────────────

class TestShamir(unittest.TestCase):

    def setUp(self):
        from crypto import shamir
        self.shamir = shamir
        self.secret = get_random_bytes(15)
        self.gen    = shamir.generate_shares(self.secret)
        self.shares = self.gen['shares']

    def test_generates_3_shares(self):
        self.assertEqual(len(self.shares), 3)

    def test_share_hospitals(self):
        hosp_ids = {s['hospital_id'] for s in self.shares}
        self.assertEqual(hosp_ids, {'Hospital_A', 'Hospital_B', 'Hospital_C'})

    def test_threshold_is_2(self):
        self.assertEqual(self.gen['threshold'], 2)

    def test_two_shares_reconstruct_A_B(self):
        shares_ab = [s for s in self.shares if s['hospital_id'] in ('Hospital_A', 'Hospital_B')]
        result = self.shamir.reconstruct_secret(shares_ab)
        self.assertTrue(result['success'], result['message'])
        self.assertTrue(self.shamir.verify_reconstruction(self.secret, result['reconstructed_hex']))

    def test_two_shares_reconstruct_A_C(self):
        shares_ac = [s for s in self.shares if s['hospital_id'] in ('Hospital_A', 'Hospital_C')]
        result = self.shamir.reconstruct_secret(shares_ac)
        self.assertTrue(result['success'])
        self.assertTrue(self.shamir.verify_reconstruction(self.secret, result['reconstructed_hex']))

    def test_two_shares_reconstruct_B_C(self):
        shares_bc = [s for s in self.shares if s['hospital_id'] in ('Hospital_B', 'Hospital_C')]
        result = self.shamir.reconstruct_secret(shares_bc)
        self.assertTrue(result['success'])
        self.assertTrue(self.shamir.verify_reconstruction(self.secret, result['reconstructed_hex']))

    def test_one_share_fails(self):
        """Single share must NOT allow reconstruction — threshold = 2."""
        one_share = self.shares[:1]
        result = self.shamir.reconstruct_secret(one_share)
        self.assertFalse(result['success'], "One share should NOT reconstruct the secret.")
        self.assertIsNone(result['reconstructed_hex'])

    def test_different_secrets_different_shares(self):
        """Two different secrets must produce different shares."""
        s1 = self.shamir.generate_shares(get_random_bytes(15))
        s2 = self.shamir.generate_shares(get_random_bytes(15))
        self.assertNotEqual(s1['shares'][0]['y_hex'], s2['shares'][0]['y_hex'])

    def test_all_three_shares_reconstruct(self):
        """3 shares (more than threshold) also reconstructs correctly."""
        result = self.shamir.reconstruct_secret(self.shares)
        self.assertTrue(result['success'])
        self.assertTrue(self.shamir.verify_reconstruction(self.secret, result['reconstructed_hex']))

    def test_key_material_derivation(self):
        """Verify derived key is 32 bytes."""
        result = self.shamir.reconstruct_secret(self.shares[:2])
        key = self.shamir.secret_to_key_material(result['reconstructed_hex'])
        self.assertEqual(len(key), 32)


# ─── Delegation Token Tests ────────────────────────────────────────────────────

class TestDelegation(unittest.TestCase):

    def setUp(self):
        from crypto import delegation
        self.dl = delegation

    def _make_token(self, minutes=60, scope='search'):
        return self.dl.create_token(
            delegator='DOCTOR_001',
            delegatee='DOCTOR_002',
            patient_id='PATIENT_001',
            hospital_id='Hospital_A',
            role='Doctor',
            duration_minutes=minutes,
            scope=scope,
        )

    def test_token_is_created(self):
        t = self._make_token()
        self.assertIn('token_id', t)
        self.assertIn('signature', t)
        self.assertIn('expires_at', t)

    def test_valid_token_passes(self):
        t = self._make_token()
        result = self.dl.validate_token(t['full_token'], 'DOCTOR_002', 'PATIENT_001', 'search')
        self.assertTrue(result['valid'], result['reason'])
        self.assertTrue(result['sig_valid'])
        self.assertTrue(result['time_valid'])
        self.assertTrue(result['delegatee_match'])
        self.assertTrue(result['patient_match'])
        self.assertTrue(result['scope_valid'])

    def test_tampered_signature_rejected(self):
        """Modifying any field in the token must invalidate the signature."""
        t = self._make_token()
        tampered = dict(t['full_token'])
        tampered['delegatee'] = 'DOCTOR_EVIL'  # Tamper
        result = self.dl.validate_token(tampered, 'DOCTOR_EVIL', 'PATIENT_001', 'search')
        self.assertFalse(result['valid'])
        self.assertFalse(result['sig_valid'])

    def test_expired_token_rejected(self):
        """Expired token must be rejected on time check."""
        t = self._make_token()
        expired = self.dl.force_expire_token(t['full_token'])
        result = self.dl.validate_token(expired, 'DOCTOR_002', 'PATIENT_001', 'search')
        self.assertFalse(result['valid'])
        self.assertFalse(result['time_valid'])
        self.assertTrue(result['sig_valid'])  # Sig still valid, only time failed

    def test_wrong_delegatee_rejected(self):
        t = self._make_token()
        result = self.dl.validate_token(t['full_token'], 'DOCTOR_009', 'PATIENT_001', 'search')
        self.assertFalse(result['valid'])
        self.assertFalse(result['delegatee_match'])

    def test_wrong_patient_rejected(self):
        t = self._make_token()
        result = self.dl.validate_token(t['full_token'], 'DOCTOR_002', 'PATIENT_006', 'search')
        self.assertFalse(result['valid'])
        self.assertFalse(result['patient_match'])

    def test_scope_mismatch_rejected(self):
        """Token with scope='search' must not allow 'decrypt'."""
        t = self._make_token(scope='search')
        result = self.dl.validate_token(t['full_token'], 'DOCTOR_002', 'PATIENT_001', 'decrypt')
        self.assertFalse(result['valid'])
        self.assertFalse(result['scope_valid'])

    def test_scope_all_allows_both(self):
        """Token with scope='all' must allow both search and decrypt."""
        t = self._make_token(scope='all')
        r1 = self.dl.validate_token(t['full_token'], 'DOCTOR_002', 'PATIENT_001', 'search')
        r2 = self.dl.validate_token(t['full_token'], 'DOCTOR_002', 'PATIENT_001', 'decrypt')
        self.assertTrue(r1['valid'])
        self.assertTrue(r2['valid'])

    def test_token_fields_are_canonical(self):
        """The same token validated twice must produce the same result."""
        t = self._make_token()
        r1 = self.dl.validate_token(t['full_token'], 'DOCTOR_002', 'PATIENT_001', 'search')
        r2 = self.dl.validate_token(t['full_token'], 'DOCTOR_002', 'PATIENT_001', 'search')
        self.assertEqual(r1['valid'], r2['valid'])
        self.assertEqual(r1['sig_valid'], r2['sig_valid'])


# ─── Policy Hiding Tests ───────────────────────────────────────────────────────

class TestPolicyHiding(unittest.TestCase):

    def setUp(self):
        from crypto import policy_hiding
        self.ph = policy_hiding

    def test_builds_protected_policy(self):
        pp = self.ph.build_protected_policy('PATIENT_001', 'Hospital_A', 'Doctor', 'ACTIVE')
        self.assertIn('policy_id', pp)
        self.assertIn('protected_hospital', pp)
        self.assertIn('protected_role', pp)
        self.assertIn('protected_status', pp)
        self.assertIn('cloud_view', pp)
        self.assertIn('logical_view', pp)

    def test_cloud_view_does_not_contain_plaintext(self):
        """The cloud_view must not contain plaintext attribute values."""
        pp = self.ph.build_protected_policy('PATIENT_001', 'Hospital_A', 'Doctor', 'ACTIVE')
        cloud_str = str(pp['cloud_view'])
        self.assertNotIn('Hospital_A', cloud_str)
        self.assertNotIn('Doctor', cloud_str)
        self.assertNotIn('ACTIVE', cloud_str)
        self.assertNotIn('PATIENT_001', cloud_str)

    def test_valid_attributes_match(self):
        pp = self.ph.build_protected_policy('PATIENT_001', 'Hospital_A', 'Doctor', 'ACTIVE')
        result = self.ph.match_policy(pp, 'Hospital_A', 'Doctor', 'ACTIVE', 'PATIENT_001')
        self.assertTrue(result['match'])
        self.assertTrue(result['hospital_match'])
        self.assertTrue(result['role_match'])
        self.assertTrue(result['status_match'])

    def test_wrong_hospital_does_not_match(self):
        pp = self.ph.build_protected_policy('PATIENT_001', 'Hospital_A', 'Doctor', 'ACTIVE')
        result = self.ph.match_policy(pp, 'Hospital_B', 'Doctor', 'ACTIVE', 'PATIENT_001')
        self.assertFalse(result['match'])
        self.assertFalse(result['hospital_match'])

    def test_wrong_role_does_not_match(self):
        pp = self.ph.build_protected_policy('PATIENT_001', 'Hospital_A', 'Doctor', 'ACTIVE')
        result = self.ph.match_policy(pp, 'Hospital_A', 'Nurse', 'ACTIVE', 'PATIENT_001')
        self.assertFalse(result['match'])
        self.assertFalse(result['role_match'])

    def test_revoked_status_does_not_match_active(self):
        pp = self.ph.build_protected_policy('PATIENT_001', 'Hospital_A', 'Doctor', 'REVOKED')
        result = self.ph.match_policy(pp, 'Hospital_A', 'Doctor', 'ACTIVE', 'PATIENT_001')
        self.assertFalse(result['status_match'])

    def test_different_patients_different_policy_ids(self):
        pp1 = self.ph.build_protected_policy('PATIENT_001', 'Hospital_A', 'Doctor', 'ACTIVE')
        pp2 = self.ph.build_protected_policy('PATIENT_002', 'Hospital_A', 'Doctor', 'ACTIVE')
        self.assertNotEqual(pp1['policy_id'], pp2['policy_id'])


# ─── Verifiable Search Tests ───────────────────────────────────────────────────

class TestVerifiableSearch(unittest.TestCase):

    def setUp(self):
        from crypto import verifiable_search
        self.vs = verifiable_search
        self.keywords   = ['diabetes', 'hypertension']
        self.record_ids = ['REC_00040', 'REC_00081', 'REC_00140']

    def test_compute_returns_verification_value(self):
        result = self.vs.compute_verification(self.keywords, self.record_ids)
        self.assertIn('verification_value', result)
        self.assertEqual(len(result['verification_value']), 64)  # SHA-256 hex

    def test_correct_result_verifies(self):
        comp   = self.vs.compute_verification(self.keywords, self.record_ids)
        verify = self.vs.verify_results(self.keywords, self.record_ids, comp['verification_value'])
        self.assertTrue(verify['verified'])
        self.assertEqual(verify['status'], 'VERIFIED')

    def test_tampered_result_fails(self):
        """Adding a fake record to the result set must cause verification to fail."""
        comp     = self.vs.compute_verification(self.keywords, self.record_ids)
        tampered = self.record_ids + ['FAKE_RECORD_999']
        verify   = self.vs.verify_results(self.keywords, tampered, comp['verification_value'])
        self.assertFalse(verify['verified'])
        self.assertEqual(verify['status'], 'FAILED')

    def test_dropped_record_fails(self):
        """Removing a record from the result set must cause verification to fail."""
        comp     = self.vs.compute_verification(self.keywords, self.record_ids)
        partial  = self.record_ids[:-1]  # Drop last record
        verify   = self.vs.verify_results(self.keywords, partial, comp['verification_value'])
        self.assertFalse(verify['verified'])

    def test_different_query_fails(self):
        """Verification value for 'diabetes' must not validate a 'pneumonia' query."""
        comp   = self.vs.compute_verification(['diabetes'], self.record_ids)
        verify = self.vs.verify_results(['pneumonia'], self.record_ids, comp['verification_value'])
        self.assertFalse(verify['verified'])

    def test_result_order_independent(self):
        """Shuffled result IDs must produce same verification as sorted."""
        ids_orig     = ['REC_A', 'REC_B', 'REC_C']
        ids_shuffled = ['REC_C', 'REC_A', 'REC_B']
        v1 = self.vs.compute_verification(['diabetes'], ids_orig)['verification_value']
        v2 = self.vs.compute_verification(['diabetes'], ids_shuffled)['verification_value']
        self.assertEqual(v1, v2, "Verification must be order-independent (records sorted internally).")

    def test_empty_result_has_defined_value(self):
        """Empty result set produces a valid (non-crashing) verification value."""
        result = self.vs.compute_verification(self.keywords, [])
        self.assertIn('verification_value', result)
        self.assertEqual(result['result_count'], 0)


# ─── Integration: Consent Revocation Overrides Valid Delegation ───────────────

class TestIntegration(unittest.TestCase):
    """
    Integration test: Verify that consent revocation overrides an otherwise
    cryptographically valid delegation token.

    Uses the real application database with temporary test consent entries
    that are cleaned up after each test.
    """

    def setUp(self):
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from database import db
        from crypto.hashing import hash_user_id
        from crypto import key_manager

        self._db = db
        db.init_db()
        self._patient_hash = hash_user_id('PATIENT_TEST_INT')

        # Insert a temporary consent record for this test
        db.execute(
            """INSERT OR REPLACE INTO consent_policies
               (patient_hash, hospital_id, role, access_granted, status)
               VALUES (?,?,?,1,'ACTIVE')""",
            (self._patient_hash, 'Hospital_A', 'Doctor')
        )
        # Insert a temporary user if not exists
        db.execute(
            """INSERT OR IGNORE INTO users
               (user_id, user_hash, full_name, role, hospital_id)
               VALUES (?,?,?,?,?)""",
            ('DOCTOR_TEST_INT', hash_user_id('DOCTOR_TEST_INT'), 'Integration Test Doctor', 'Doctor', 'Hospital_A')
        )

    def tearDown(self):
        """Remove temporary test data."""
        self._db.execute(
            'DELETE FROM consent_policies WHERE patient_hash=?',
            (self._patient_hash,)
        )
        self._db.execute('DELETE FROM delegation_tokens WHERE patient_id=?', ('PATIENT_TEST_INT',))
        self._db.execute('DELETE FROM users WHERE user_id=?', ('DOCTOR_TEST_INT',))
        self._db.execute('DELETE FROM audit_log WHERE patient_hash=?', (self._patient_hash,))

    def test_delegation_consent_revocation_overrides_valid_token(self):
        """
        Core integration test:
        1. Create valid token (consent ACTIVE)   → validate → GRANTED
        2. Revoke patient consent                → validate → DENIED
        3. Cryptographic signature still valid   → only consent check failed
        """
        from services import delegation_service, consent_service
        from crypto.delegation import validate_token as dl_validate
        import json

        # Step 1: Create token — delegator has active consent
        result = delegation_service.create_token(
            delegator='DOCTOR_TEST_INT',
            delegatee='DOCTOR_002',
            patient_id='PATIENT_TEST_INT',
            hospital_id='Hospital_A',
            role='Doctor',
            duration_minutes=60,
            scope='search',
        )
        self.assertNotIn('error', result, f"Token creation failed: {result}")
        token_id = result['token_id']

        # Step 2: Validate before revocation — must PASS
        v1 = delegation_service.validate_token(token_id, 'DOCTOR_002', 'PATIENT_TEST_INT', 'search')
        self.assertTrue(v1['valid'], f"Expected GRANTED but got: {v1['reason']}")
        self.assertTrue(v1['consent_active'])
        self.assertTrue(v1['sig_valid'])

        # Step 3: Revoke consent
        consent_service.revoke(self._patient_hash, 'Hospital_A', 'Doctor', actor='integration_test')

        # Step 4: Validate same token after revocation — must DENY
        v2 = delegation_service.validate_token(token_id, 'DOCTOR_002', 'PATIENT_TEST_INT', 'search')
        self.assertFalse(v2['valid'], "Token must be DENIED after consent revocation.")
        self.assertFalse(v2['consent_active'])
        # The cryptographic signature must still be valid — only consent failed
        self.assertTrue(v2['sig_valid'], "Signature must remain valid — only consent changed.")

    def test_expired_token_is_denied_regardless_of_consent(self):
        """Even with active consent, an expired token must be DENIED."""
        from crypto import delegation as dl
        result = dl.create_token(
            delegator='DOCTOR_TEST_INT',
            delegatee='DOCTOR_002',
            patient_id='PATIENT_TEST_INT',
            hospital_id='Hospital_A',
            role='Doctor',
            duration_minutes=60,
        )
        expired = dl.force_expire_token(result['full_token'])
        v = dl.validate_token(expired, 'DOCTOR_002', 'PATIENT_TEST_INT', 'search')
        self.assertFalse(v['valid'])
        self.assertFalse(v['time_valid'])
        self.assertTrue(v['sig_valid'])




# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("  MASE-SE — Advanced Feature Tests (40% Extension)")
    print("=" * 60)
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()
    for cls in [TestShamir, TestDelegation, TestPolicyHiding, TestVerifiableSearch, TestIntegration]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
