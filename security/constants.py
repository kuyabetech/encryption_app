"""
Cryptographic constants and configuration.
Never change these for existing files - use versioning instead.
"""

import os

# Algorithm identifiers
MAGIC_HEADER = b'ENCv1'  # 5 bytes magic header
CURRENT_VERSION = 1
ALGORITHM_AES256_GCM = 1

# Key derivation parameters (Argon2id)
# These values are for development. Production should increase memory cost.
ARGON2_TIME_COST = 2          # Number of iterations
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB
ARGON2_PARALLELISM = 1        # Single thread (prevents DoS)
ARGON2_HASH_LEN = 32          # 256-bit output

# Alternative: PBKDF2 parameters (if Argon2 not available)
PBKDF2_ITERATIONS = 600000
PBKDF2_HASH_ALGORITHM = 'sha256'

# AES parameters
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12  # 96 bits for GCM (recommended)
AES_TAG_SIZE = 16   # 128-bit authentication tag

# File format
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB limit for safety
CHUNK_SIZE = 64 * 1024  # 64KB chunks for large files

# Security
MIN_PASSWORD_LENGTH = 12
SALT_SIZE = 16  # 128-bit salt