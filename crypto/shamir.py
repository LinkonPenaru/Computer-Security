"""
crypto/shamir.py
================
Real Shamir (2, 3) Secret Sharing over GF(p) where p = 2^127 - 1 (Mersenne prime).

HOW IT WORKS
------------
Given a secret integer S in [0, p):

  1. Pick a random coefficient a1 in [1, p).
  2. Define polynomial: f(x) = S + a1*x  (mod p)
     (degree-1 polynomial → threshold = 2)
  3. Evaluate at x = 1, 2, 3 to produce three shares.
  4. Any two shares allow Lagrange interpolation to recover f(0) = S.
  5. One share alone gives no information about S.

SECURITY NOTE
-------------
This is a standard (k=2, n=3) Shamir Secret Sharing scheme implemented
over a Mersenne prime field. It is information-theoretically secure:
one share alone reveals zero information about the secret.
This is NOT a full MPC protocol — it is the secret-sharing primitive
used as the key distribution mechanism in MASE-SE.
"""

import os
import hashlib
import base64

# Mersenne prime p = 2^127 - 1
# This gives a 127-bit field — larger than AES-256 key (256 bits needs careful handling).
# For the demo we share a 128-bit secret that fits in [0, p).
PRIME = (1 << 127) - 1


# ─── Core Field Arithmetic ────────────────────────────────────────────────────

def _mod_inverse(a: int, p: int) -> int:
    """Extended Euclidean Algorithm — compute a^(-1) mod p."""
    if a == 0:
        raise ZeroDivisionError("No inverse for 0")
    old_r, r = a % p, p
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % p


def _lagrange_interpolate(x: int, x_vals: list, y_vals: list, p: int) -> int:
    """
    Lagrange interpolation at point x over GF(p).
    Used to evaluate the secret polynomial at x=0.
    """
    result = 0
    for i, xi in enumerate(x_vals):
        # Compute numerator and denominator of basis polynomial L_i(x)
        num = 1
        den = 1
        for j, xj in enumerate(x_vals):
            if i == j:
                continue
            num = (num * (x - xj)) % p
            den = (den * (xi - xj)) % p
        result = (result + y_vals[i] * num * _mod_inverse(den, p)) % p
    return result


# ─── Public API ───────────────────────────────────────────────────────────────

def generate_shares(secret_bytes: bytes) -> dict:
    """
    Split secret_bytes into 3 Shamir shares with threshold = 2.

    Parameters
    ----------
    secret_bytes : bytes
        The secret to protect (up to 15 bytes to fit in [0, PRIME)).

    Returns
    -------
    dict with keys:
        'shares'      : list of 3 dicts, each with 'hospital_id', 'x', 'y_hex'
        'prime_hex'   : the field prime as hex
        'threshold'   : 2
        'n_shares'    : 3
        'secret_hash' : SHA-256(secret_bytes) as hex — used for verification only
    """
    if len(secret_bytes) > 15:
        # Truncate/hash to fit in field — we share the first 15 bytes
        secret_bytes = hashlib.sha256(secret_bytes).digest()[:15]

    secret_int = int.from_bytes(secret_bytes, 'big') % PRIME

    # Random coefficient a1 in [1, PRIME)
    a1 = int.from_bytes(os.urandom(15), 'big') % (PRIME - 1) + 1

    # Polynomial: f(x) = secret + a1 * x  (mod PRIME)
    hospitals = ['Hospital_A', 'Hospital_B', 'Hospital_C']
    shares = []
    for idx, hosp in enumerate(hospitals, start=1):
        x = idx
        y = (secret_int + a1 * x) % PRIME
        shares.append({
            'hospital_id': hosp,
            'x':           x,
            'y_hex':       hex(y),
        })

    return {
        'shares':      shares,
        'prime_hex':   hex(PRIME),
        'threshold':   2,
        'n_shares':    3,
        'secret_hash': hashlib.sha256(secret_bytes).hexdigest(),
    }


def reconstruct_secret(shares: list) -> dict:
    """
    Attempt to reconstruct the secret from a subset of shares.

    Parameters
    ----------
    shares : list of dicts, each with 'x' (int) and 'y_hex' (str)
        Provide 2 or more shares for reconstruction.
        Provide 1 share to demonstrate failure.

    Returns
    -------
    dict:
        'success'       : bool
        'reconstructed_hex' : hex string of reconstructed secret (if success)
        'shares_used'   : int
        'threshold'     : 2
        'message'       : human-readable status
    """
    n = len(shares)
    if n < 2:
        return {
            'success':            False,
            'reconstructed_hex':  None,
            'shares_used':        n,
            'threshold':          2,
            'message': (
                f"RECONSTRUCTION FAILED: only {n} share(s) provided. "
                "Threshold is 2. One share reveals ZERO information about the secret."
            ),
        }

    # Use only first 2 shares if more provided (threshold = 2)
    working = shares[:2]
    x_vals = [s['x'] for s in working]
    y_vals = [int(s['y_hex'], 16) for s in working]

    reconstructed_int = _lagrange_interpolate(0, x_vals, y_vals, PRIME)
    reconstructed_hex = hex(reconstructed_int)

    return {
        'success':           True,
        'reconstructed_hex': reconstructed_hex,
        'shares_used':       n,
        'threshold':         2,
        'message':           f"RECONSTRUCTION SUCCESS: {n} share(s) used, threshold = 2.",
    }


def verify_reconstruction(original_secret_bytes: bytes, reconstructed_hex: str) -> bool:
    """
    Verify that the reconstructed integer matches the original secret.

    Parameters
    ----------
    original_secret_bytes : bytes — original secret
    reconstructed_hex     : str  — hex integer from reconstruct_secret()

    Returns
    -------
    bool : True if they match
    """
    if len(original_secret_bytes) > 15:
        original_secret_bytes = hashlib.sha256(original_secret_bytes).digest()[:15]
    original_int = int.from_bytes(original_secret_bytes, 'big') % PRIME
    return int(reconstructed_hex, 16) == original_int


def secret_to_key_material(reconstructed_hex: str) -> bytes:
    """
    Derive a 32-byte key from the reconstructed integer using SHA-256.
    This is used to derive a session key from the reconstructed secret.
    """
    raw = int(reconstructed_hex, 16).to_bytes(16, 'big')
    return hashlib.sha256(raw).digest()
