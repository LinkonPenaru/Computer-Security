"""
services/delegation_service.py
================================
Database-backed delegation token management.

Wraps crypto/delegation.py with persistence and consent-aware validation.
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import db
from crypto import delegation as dl
from services import audit_service, consent_service


def create_token(
    delegator:        str,
    delegatee:        str,
    patient_id:       str,
    hospital_id:      str,
    role:             str,
    duration_minutes: int = 60,
    scope:            str = 'search',
) -> dict:
    """
    Create and persist a signed delegation token.

    Verifies that the delegator has active consent for the patient/hospital/role
    before issuing the token. The delegator cannot grant more than they hold.

    Returns
    -------
    dict from crypto.delegation.create_token() plus 'stored': bool
    """
    # Verify delegator has consent
    from crypto.hashing import hash_user_id
    patient_hash = hash_user_id(patient_id)

    if not consent_service.is_access_granted(patient_hash, hospital_id, role):
        audit_service.log(
            'DELEGATION_DENIED',
            user_id=delegator,
            patient_hash=patient_hash,
            details=f'Delegator {delegator} has no active consent — cannot delegate.',
            success=False,
        )
        return {
            'error': 'Delegator does not hold active consent for this patient/hospital/role.',
            'stored': False,
        }

    token_result = dl.create_token(
        delegator=delegator,
        delegatee=delegatee,
        patient_id=patient_id,
        hospital_id=hospital_id,
        role=role,
        duration_minutes=duration_minutes,
        scope=scope,
    )

    full_token = token_result['full_token']

    db.execute(
        """INSERT OR REPLACE INTO delegation_tokens
           (token_id, delegator, delegatee, patient_id, hospital_id,
            role, scope, issued_at, expires_at, full_token_json)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            token_result['token_id'],
            delegator,
            delegatee,
            patient_id,
            hospital_id,
            role,
            scope,
            full_token['issued_at'],
            token_result['expires_at'],
            json.dumps(full_token),
        )
    )

    audit_service.log(
        'DELEGATION_CREATED',
        user_id=delegator,
        patient_hash=patient_hash,
        details=f'Token {token_result["token_id"]} → {delegatee}, expires {token_result["expires_at"]}',
        success=True,
    )

    token_result['stored'] = True
    return token_result


def validate_token(token_id: str, requesting_user: str, patient_id: str, operation: str = 'search') -> dict:
    """
    Load a stored token and validate it for a specific access attempt.

    Steps:
      1. Load token from DB.
      2. Check it has not been manually revoked.
      3. Cryptographically validate via crypto.delegation.validate_token().
      4. Check patient consent is still active (consent can override delegation).

    Returns
    -------
    dict with 'valid', 'reason', and all validation sub-results.
    """
    row = db.fetchone('SELECT * FROM delegation_tokens WHERE token_id=?', (token_id,))

    if not row:
        return {
            'valid': False,
            'reason': f'Token {token_id} not found in the system.',
            'sig_valid': False,
            'time_valid': False,
            'delegatee_match': False,
            'patient_match': False,
            'scope_valid': False,
            'consent_active': False,
            'token_id': token_id,
        }

    if row['revoked']:
        return {
            'valid': False,
            'reason': 'Token has been manually revoked.',
            'sig_valid': True,
            'time_valid': None,
            'delegatee_match': None,
            'patient_match': None,
            'scope_valid': None,
            'consent_active': None,
            'token_id': token_id,
        }

    full_token = json.loads(row['full_token_json'])
    crypto_result = dl.validate_token(full_token, requesting_user, patient_id, operation)

    # Also check patient consent is still active (consent revocation overrides delegation)
    from crypto.hashing import hash_user_id
    patient_hash = hash_user_id(patient_id)
    consent_active = consent_service.is_access_granted(
        patient_hash, row['hospital_id'], row['role']
    )

    overall_valid = crypto_result['valid'] and consent_active

    result = dict(crypto_result)
    result['consent_active'] = consent_active
    result['valid'] = overall_valid
    if not consent_active and crypto_result['valid']:
        result['reason'] = 'Patient consent has been revoked — delegation token is no longer effective.'

    event_type = 'DELEGATION_ACCESS_GRANTED' if overall_valid else 'DELEGATION_ACCESS_DENIED'
    audit_service.log(
        event_type,
        user_id=requesting_user,
        patient_hash=patient_hash,
        details=f"Token {token_id} | sig={result['sig_valid']} time={result['time_valid']} consent={consent_active}",
        success=overall_valid,
    )

    return result


def list_tokens(patient_id: str = None, delegatee: str = None, limit: int = 20) -> list:
    """Return stored delegation tokens, optionally filtered."""
    if patient_id and delegatee:
        rows = db.fetchall(
            'SELECT * FROM delegation_tokens WHERE patient_id=? AND delegatee=? ORDER BY created_at DESC LIMIT ?',
            (patient_id, delegatee, limit)
        )
    elif patient_id:
        rows = db.fetchall(
            'SELECT * FROM delegation_tokens WHERE patient_id=? ORDER BY created_at DESC LIMIT ?',
            (patient_id, limit)
        )
    elif delegatee:
        rows = db.fetchall(
            'SELECT * FROM delegation_tokens WHERE delegatee=? ORDER BY created_at DESC LIMIT ?',
            (delegatee, limit)
        )
    else:
        rows = db.fetchall(
            'SELECT * FROM delegation_tokens ORDER BY created_at DESC LIMIT ?', (limit,)
        )
    return [dict(r) for r in rows]


def revoke_token(token_id: str, actor: str = 'system') -> bool:
    """Manually revoke a delegation token (soft delete)."""
    db.execute('UPDATE delegation_tokens SET revoked=1 WHERE token_id=?', (token_id,))
    audit_service.log('DELEGATION_MANUALLY_REVOKED', user_id=actor,
                      details=f'Token {token_id} revoked.', success=True)
    return True


def get_expired_demo_token(token_id: str) -> dict:
    """
    Return a version of the token with expires_at set in the past.
    Used for the teacher expiry demonstration.
    The returned dict is NOT persisted — it is used only for the demo validation call.
    """
    row = db.fetchone('SELECT * FROM delegation_tokens WHERE token_id=?', (token_id,))
    if not row:
        return {}
    full_token = json.loads(row['full_token_json'])
    return dl.force_expire_token(full_token)
