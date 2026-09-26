"""
services/search_service.py
===========================
Keyword search over the protected (HMAC) search index.

Workflow:
  1. User enters keyword(s) in the UI.
  2. Application computes: SearchToken = HMAC-SHA256(K_search, keyword)
  3. Token is looked up in the search_index table.
  4. For multiple keywords: the result sets are INTERSECTED (AND logic).
  5. The cloud layer returns encrypted record IDs.
  6. Authorization is checked before any decryption.

The cloud NEVER decrypts every record to find matches.
The cloud NEVER sees the plaintext keyword — only the HMAC token.
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List
from database import db
from crypto import searchable_encryption as se, key_manager
from services import audit_service


def search(user_id: str,
           keywords: List[str],
           hospital_ids: List[str] = None) -> dict:
    """
    Search the protected index for records matching ALL given keywords.

    Parameters
    ----------
    user_id     : str        — acting user (for audit)
    keywords    : List[str]  — plaintext keywords from the user's query
    hospital_ids: List[str]  — which hospitals to search (None = all)

    Returns
    -------
    dict:
        keywords       : original keywords
        search_tokens  : list of {keyword, token} — shows what cloud receives
        record_ids     : list of matching record IDs
        record_count   : int
        search_time_ms : float
        hospitals_searched : list
    """
    t_start = time.perf_counter()

    if not keywords:
        return _empty_result([], [], 0.0)

    # Clean keywords
    kws = [k.strip().lower() for k in keywords if k.strip()]
    if not kws:
        return _empty_result([], [], 0.0)

    hospitals = hospital_ids or ["Hospital_A", "Hospital_B", "Hospital_C"]

    # Generate protected search tokens and collect matching record sets
    tokens_info = []
    result_sets = []

    for hosp in hospitals:
        try:
            search_key = key_manager.get_search_key(hosp)
        except KeyError:
            continue  # hospital key not loaded yet

        for kw in kws:
            token = se.generate_search_token(kw, search_key)

            # Check if we already have this token in tokens_info
            if not any(t["keyword"] == kw for t in tokens_info):
                tokens_info.append({"keyword": kw, "token": token[:16] + "…"})

            # Look up records in the protected index
            rows = db.fetchall(
                "SELECT record_id FROM search_index WHERE hospital_id=? AND search_token=?",
                (hosp, token),
            )
            ids = {r["record_id"] for r in rows}
            result_sets.append(ids)

    # Conjunctive search: intersect all result sets
    if not result_sets:
        matched_ids = set()
    elif len(result_sets) == 1:
        matched_ids = result_sets[0]
    else:
        # For multi-keyword: intersect sets from the SAME hospital
        # We need per-hospital intersection then union across hospitals
        matched_ids = _conjunctive_search(hospitals, kws)

    t_end = time.perf_counter()
    search_ms = (t_end - t_start) * 1000

    record_ids = sorted(matched_ids)

    audit_service.log(
        "SEARCH",
        user_id  = user_id,
        details  = f"keywords={kws}, hospitals={hospitals}, matches={len(record_ids)}",
        success  = True,
    )

    return {
        "keywords":           kws,
        "search_tokens":      tokens_info,
        "record_ids":         record_ids,
        "record_count":       len(record_ids),
        "search_time_ms":     round(search_ms, 3),
        "hospitals_searched": hospitals,
    }


def _conjunctive_search(hospitals: List[str], kws: List[str]) -> set:
    """
    For each hospital, find records matching ALL keywords, then union results.
    """
    all_matched = set()
    for hosp in hospitals:
        try:
            search_key = key_manager.get_search_key(hosp)
        except KeyError:
            continue

        hosp_sets = []
        for kw in kws:
            token = se.generate_search_token(kw, search_key)
            rows  = db.fetchall(
                "SELECT record_id FROM search_index WHERE hospital_id=? AND search_token=?",
                (hosp, token),
            )
            hosp_sets.append({r["record_id"] for r in rows})

        if hosp_sets:
            intersection = hosp_sets[0].intersection(*hosp_sets[1:])
            all_matched.update(intersection)

    return all_matched


def _empty_result(kws, tokens_info, ms) -> dict:
    return {
        "keywords":           kws,
        "search_tokens":      tokens_info,
        "record_ids":         [],
        "record_count":       0,
        "search_time_ms":     ms,
        "hospitals_searched": [],
    }
