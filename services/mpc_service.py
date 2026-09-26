"""
services/mpc_service.py
========================
MPC session management for Shamir (2,3) secret sharing.

Wraps crypto/shamir.py with database persistence.
Each MPC session generates 3 shares (one per hospital) and stores them
in the mpc_sessions table. Reconstruction is attempted from a caller-supplied
subset of shares.
"""

import sys, os, json, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Random import get_random_bytes
from database import db
from crypto import shamir
from services import audit_service


def generate_session(purpose: str = 'key_derivation', notes: str = '') -> dict:
    """
    Generate a new Shamir (2,3) MPC session.

    A fresh 15-byte random secret is generated and split into 3 shares.
    The secret itself is NOT stored — only the shares and the SHA-256 hash
    of the secret are persisted. This mirrors what would happen in a real
    MPC setup: each hospital stores only its own share.

    Returns
    -------
    dict:
        'session_id' : str
        'shares'     : list of 3 share dicts (x, y_hex, hospital_id)
        'secret_hash': str — SHA-256 hex of the secret (for verification)
        'threshold'  : 2
        'n_shares'   : 3
        'prime_hex'  : str
    """
    secret_bytes = get_random_bytes(15)
    result = shamir.generate_shares(secret_bytes)

    session_id = str(uuid.uuid4())
    shares = result['shares']  # list: [{hospital_id, x, y_hex}, ...]

    db.execute(
        """INSERT INTO mpc_sessions
           (session_id, secret_hash, share_a_x, share_a_y_hex,
            share_b_x, share_b_y_hex, share_c_x, share_c_y_hex,
            prime_hex, threshold, n_shares, purpose, notes)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            session_id,
            result['secret_hash'],
            shares[0]['x'], shares[0]['y_hex'],
            shares[1]['x'], shares[1]['y_hex'],
            shares[2]['x'], shares[2]['y_hex'],
            result['prime_hex'],
            result['threshold'],
            result['n_shares'],
            purpose,
            notes,
        )
    )

    audit_service.log(
        'MPC_SESSION_CREATED',
        details=f"Session {session_id} — Shamir (2,3) shares generated for {purpose}",
        success=True,
    )

    return {
        'session_id':  session_id,
        'shares':      shares,
        'secret_hash': result['secret_hash'],
        'threshold':   result['threshold'],
        'n_shares':    result['n_shares'],
        'prime_hex':   result['prime_hex'],
    }


def get_session(session_id: str) -> dict | None:
    """Retrieve a stored MPC session by ID."""
    row = db.fetchone('SELECT * FROM mpc_sessions WHERE session_id=?', (session_id,))
    if not row:
        return None
    return dict(row)


def reconstruct_from_hospitals(session_id: str, hospital_ids: list) -> dict:
    """
    Attempt reconstruction using shares from the specified hospitals.

    Parameters
    ----------
    session_id   : str — existing MPC session
    hospital_ids : list of str — subset of ['Hospital_A','Hospital_B','Hospital_C']

    Returns
    -------
    dict from shamir.reconstruct_secret() plus session metadata.
    """
    row = get_session(session_id)
    if not row:
        return {'success': False, 'message': f'Session {session_id} not found.'}

    # Map hospital names to stored shares
    share_map = {
        'Hospital_A': {'x': row['share_a_x'], 'y_hex': row['share_a_y_hex']},
        'Hospital_B': {'x': row['share_b_x'], 'y_hex': row['share_b_y_hex']},
        'Hospital_C': {'x': row['share_c_x'], 'y_hex': row['share_c_y_hex']},
    }

    requested_shares = []
    valid_hospitals  = []
    for h in hospital_ids:
        if h in share_map:
            requested_shares.append(share_map[h])
            valid_hospitals.append(h)

    result = shamir.reconstruct_secret(requested_shares)
    result['session_id']       = session_id
    result['hospitals_used']   = valid_hospitals
    result['secret_hash']      = row['secret_hash']
    result['purpose']          = row['purpose']
    result['prime_hex']        = row['prime_hex']

    event_type = 'MPC_RECONSTRUCT_SUCCESS' if result['success'] else 'MPC_RECONSTRUCT_FAILED'
    audit_service.log(
        event_type,
        details=f"Session {session_id} — hospitals={valid_hospitals} shares={len(requested_shares)}",
        success=result['success'],
    )

    return result


def list_sessions(limit: int = 10) -> list:
    """Return the most recent MPC sessions (metadata only, no share values)."""
    rows = db.fetchall(
        """SELECT session_id, created_at, secret_hash, threshold, n_shares, purpose, notes
           FROM mpc_sessions ORDER BY created_at DESC LIMIT ?""",
        (limit,)
    )
    return [dict(r) for r in rows]
