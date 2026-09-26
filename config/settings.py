"""
MASE-SE Configuration
=====================
All paths and constants are defined here.
Change DATABASE_PATH or MIMIC_DATA_DIR if your layout differs.
"""
import os

# Project root = parent of this file's directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SQLite database file
DATABASE_PATH = os.path.join(BASE_DIR, "database", "mase_se.db")

# MIMIC-IV raw data folder (the hosp/ directory)
MIMIC_DATA_DIR = os.path.join(BASE_DIR, "hosp")

# Directory for processed data / exports
DATA_DIR = os.path.join(BASE_DIR, "data")

# Maximum number of MIMIC records to import (10 000)
MAX_RECORDS = 10_000

# Flask secret key (used for session signing in the prototype)
FLASK_SECRET_KEY = "mase-se-demo-2026-research"

# Hospitals simulated in this prototype
HOSPITALS = ["Hospital_A", "Hospital_B", "Hospital_C"]

# Roles recognised by the authorization engine
ROLES = ["Doctor", "Nurse", "Researcher", "Patient"]

# -----------------------------------------------------------------------
# NOTE ON CRYPTOGRAPHIC KEYS
# -----------------------------------------------------------------------
# In this 60% prototype, each hospital's AES-256 key and HMAC search key
# are generated once and stored (encrypted) in the database.
#
# Future 40% extension: replace with MPC / Shamir (2-of-3) threshold
# secret sharing so that no single hospital ever holds a complete key.
# -----------------------------------------------------------------------
