"""
crypto/searchable_encryption.py
================================
HMAC-SHA256 protected keyword search (Searchable Symmetric Encryption).

IMPLEMENTED MECHANISM (60% prototype):
  SearchToken = HMAC-SHA256(K_search, keyword.lower())

  The cloud stores these tokens in the search index.
  When a user searches, the application computes the same token and
  looks it up in the index.  The cloud NEVER sees the plaintext keyword.

FUTURE EXTENSION (40%):
  Trapdoor will encode both the keyword AND the user's attribute context,
  so the cloud can enforce attribute-level search restrictions.

HOW IT WORKS:
  1. At index-build time:
       keyword "diabetes"  →  HMAC(K_search, "diabetes")  →  token_X
       token_X  →  [record_001, record_020, record_311, ...]  (stored in DB)

  2. At search time:
       user types "diabetes"  →  HMAC(K_search, "diabetes")  →  token_X
       cloud looks up token_X → returns encrypted record IDs

  The cloud sees only token_X, not the word "diabetes".
"""

import hmac
import hashlib
from typing import List, Set


def generate_search_token(keyword: str, search_key: bytes) -> str:
    """
    Generate an HMAC-SHA256 protected search token for a keyword.

    Parameters
    ----------
    keyword    : str   — plaintext keyword (e.g. "diabetes")
    search_key : bytes — 32-byte HMAC key for this hospital

    Returns
    -------
    str : 64-character hex HMAC digest (the protected token)
    """
    return hmac.new(
        search_key,
        keyword.strip().lower().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_tokens_for_keywords(keywords: List[str], search_key: bytes) -> List[str]:
    """
    Generate protected search tokens for a list of keywords.
    Empty or whitespace-only keywords are skipped.
    """
    return [
        generate_search_token(kw, search_key)
        for kw in keywords
        if kw.strip()
    ]


def extract_keywords_from_diagnosis(long_title: str) -> List[str]:
    """
    Extract meaningful searchable keywords from an ICD diagnosis description.

    Steps:
      1. Lowercase and split into words.
      2. Remove punctuation characters.
      3. Remove common medical stopwords and short words (< 4 characters).
      4. Deduplicate.

    Parameters
    ----------
    long_title : str — e.g. "Type 2 diabetes mellitus with diabetic nephropathy"

    Returns
    -------
    List[str] : e.g. ["diabetes", "mellitus", "diabetic", "nephropathy"]
    """
    STOPWORDS: Set[str] = {
        "of", "the", "with", "and", "or", "in", "to", "a", "an", "for",
        "due", "type", "unspecified", "other", "nos", "not", "by", "as",
        "at", "on", "is", "are", "was", "be", "from", "into", "that",
        "this", "which", "without", "use", "using", "history", "status",
        "care", "acute", "chronic", "initial", "encounter", "subsequent",
        "complication", "associated", "related", "involving", "affecting",
    }
    if not long_title:
        return []

    # Basic cleanup
    cleaned = (
        long_title.lower()
        .replace(",", " ").replace("(", " ").replace(")", " ")
        .replace(";", " ").replace(":", " ").replace("/", " ")
        .replace("-", " ").replace("'", "")
    )

    words = cleaned.split()
    keywords = [
        w for w in words
        if len(w) >= 4 and w not in STOPWORDS and w.isalpha()
    ]
    return list(dict.fromkeys(keywords))  # deduplicate, preserve order
