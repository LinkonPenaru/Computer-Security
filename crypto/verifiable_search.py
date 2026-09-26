"""
crypto/verifiable_search.py
============================
Blockchain-free search result verification using HMAC-SHA256 accumulator.

PURPOSE
-------
Allow a client to verify that the cloud returned a COMPLETE and UNMODIFIED
set of search results for a given query — without relying on a blockchain,
a trusted third party, or any external infrastructure.

HOW IT WORKS
------------
At search time, the server computes a verification value V that is
bound to BOTH the query and the exact result set:

  1. Normalize the query (lowercase, sorted keywords).
  2. Compute: query_hash = SHA-256(normalized_query)
  3. Sort the returned record_ids lexicographically.
  4. Build canonical result string: record_ids joined by '|'
  5. Compute accumulator:
         V = HMAC-SHA256(K_verify, query_hash || canonical_results)

The client receives V alongside the result set.

VERIFICATION
------------
To verify, the client (or the same server call) re-computes V from the
same query and result set and checks that it matches.

If the cloud:
  - Drops any record from the result   → V will not match
  - Adds a fake record to the result   → V will not match
  - Returns results for a different query → V will not match

TAMPERING DEMONSTRATION
-----------------------
For the teacher demonstration:
  1. Server computes V for the real result set R.
  2. Dashboard shows V = VERIFIED.
  3. User clicks [Simulate Tampering] → adds a fake record to R.
  4. Client re-computes V for the tampered R → MISMATCH → FAILED.
  5. User clicks [Restore] → re-computes V for original R → VERIFIED.

SECURITY NOTE
-------------
This is a HMAC-based verification scheme (not a cryptographic accumulator
in the formal complexity-theoretic sense). It provides integrity detection
against passive result manipulation. The verification key K_verify is held
by the application layer, not the cloud, which is consistent with the
trust model of MASE-SE.
"""

import hmac
import hashlib
from typing import List, Optional

# Verification key — 32 bytes derived from a fixed seed for the prototype.
_VERIFY_KEY: Optional[bytes] = None


def _get_verify_key() -> bytes:
    """Return (or derive) the verification key."""
    global _VERIFY_KEY
    if _VERIFY_KEY is None:
        seed = b"mase-se-verify-key-2026-research"
        _VERIFY_KEY = hashlib.sha256(seed).digest()
    return _VERIFY_KEY


def _normalize_query(keywords: list) -> str:
    """
    Normalize a list of keywords into a canonical string.
    Lower-case, stripped, sorted — order-independent.
    """
    return '|'.join(sorted(k.strip().lower() for k in keywords if k.strip()))


def _canonical_results(record_ids: list) -> str:
    """
    Sort record IDs lexicographically and join with '|'.
    This makes the accumulator independent of return order.
    """
    return '|'.join(sorted(str(r) for r in record_ids))


# ─── Public API ───────────────────────────────────────────────────────────────

def compute_verification(keywords: list, record_ids: list) -> dict:
    """
    Compute a verification value for a search query and its result set.

    Parameters
    ----------
    keywords   : list of str — the search keywords
    record_ids : list of str — the returned record identifiers

    Returns
    -------
    dict:
        'query_normalized'    : str — canonical query representation
        'query_hash'          : str — SHA-256 hex of normalized query
        'result_canonical'    : str — sorted, pipe-joined record IDs
        'result_count'        : int
        'verification_value'  : str — HMAC-SHA256 hex (the accumulator)
        'algorithm'           : str — description of what was computed
    """
    key = _get_verify_key()

    # Step 1 — normalize query
    normalized_query = _normalize_query(keywords)
    query_hash = hashlib.sha256(normalized_query.encode('utf-8')).hexdigest()

    # Step 2 — canonical results
    canonical_results = _canonical_results(record_ids)

    # Step 3 — HMAC over (query_hash || canonical_results)
    message = (query_hash + '||' + canonical_results).encode('utf-8')
    verification_value = hmac.new(key, message, hashlib.sha256).hexdigest()

    return {
        'query_normalized':   normalized_query,
        'query_hash':         query_hash,
        'result_canonical':   canonical_results,
        'result_count':       len(record_ids),
        'verification_value': verification_value,
        'algorithm':          'HMAC-SHA256(K_verify, SHA256(query) || sorted_record_ids)',
    }


def verify_results(
    keywords:           list,
    record_ids:         list,
    expected_value:     str,
) -> dict:
    """
    Verify a returned result set against a previously computed verification value.

    Parameters
    ----------
    keywords       : list of str — same keywords as original search
    record_ids     : list of str — result set to verify (may be tampered)
    expected_value : str — verification_value from compute_verification()

    Returns
    -------
    dict:
        'verified'            : bool
        'computed_value'      : str — freshly computed HMAC
        'expected_value'      : str — original HMAC
        'match'               : bool
        'result_count'        : int
        'status'              : 'VERIFIED' | 'FAILED'
        'message'             : human-readable
    """
    fresh = compute_verification(keywords, record_ids)
    computed = fresh['verification_value']

    match = hmac.compare_digest(computed, expected_value)

    return {
        'verified':       match,
        'computed_value': computed,
        'expected_value': expected_value,
        'match':          match,
        'result_count':   len(record_ids),
        'query_hash':     fresh['query_hash'],
        'status':         'VERIFIED' if match else 'FAILED',
        'message': (
            'Search result integrity confirmed. The returned set matches the original query.'
            if match else
            'INTEGRITY FAILURE: The returned result set does not match the original verification value. '
            'The result may have been tampered with.'
        ),
    }
