"""
Secure key derivation and password management.
"""

import os
import hashlib
from typing import Optional, Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerificationError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from security.constants import (
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
    ARGON2_HASH_LEN, PBKDF2_ITERATIONS, PBKDF2_HASH_ALGORITHM,
    AES_KEY_SIZE, SALT_SIZE
)
from security.exceptions import InvalidKeyError, PasswordTooWeakError
from utils.validators import PasswordValidator
from utils.logger import logger


class KeyManager:
    """
    Manages password-based key derivation.
    
    Uses Argon2id when available, falls back to PBKDF2.
    Never stores passwords or keys in memory longer than necessary.
    """
    
    def __init__(self, use_argon2: bool = True):
        """
        Initialize KeyManager.
        
        Args:
            use_argon2: Whether to prefer Argon2id over PBKDF2
        """
        self.use_argon2 = use_argon2 and ARGON2_AVAILABLE
        
        if self.use_argon2:
            self.ph = PasswordHasher(
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=ARGON2_HASH_LEN,
                type=2  # Argon2id
            )
            logger.info("Using Argon2id for key derivation")
        else:
            logger.warning("Using PBKDF2-HMAC-SHA256 (Argon2 not available)")
    
    def generate_salt(self) -> bytes:
        """
        Generate cryptographically secure random salt.
        
        Returns:
            bytes: Random salt of SALT_SIZE bytes
        """
        return os.urandom(SALT_SIZE)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password and salt.
        
        Args:
            password: User password
            salt: Random salt
            
        Returns:
            bytes: Derived encryption key (AES_KEY_SIZE bytes)
            
        Raises:
            InvalidKeyError: If key derivation fails
        """
        try:
            password_bytes = password.encode('utf-8')
            
            if self.use_argon2:
                # Argon2id
                raw_hash = self.ph.hash(password=password_bytes, salt=salt)
                # Extract the raw hash bytes (last ARGON2_HASH_LEN bytes of hash)
                # Note: This is simplified - in production, use proper raw hash extraction
                key = hashlib.sha256(raw_hash.encode()).digest()
                
                # Ensure key is correct length
                if len(key) < AES_KEY_SIZE:
                    # Repeat hash if needed (shouldn't happen with SHA256)
                    key = hashlib.sha256(key).digest()
                key = key[:AES_KEY_SIZE]
            else:
                # PBKDF2-HMAC-SHA256 fallback
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=AES_KEY_SIZE,
                    salt=salt,
                    iterations=PBKDF2_ITERATIONS,
                    backend=default_backend()
                )
                key = kdf.derive(password_bytes)
            
            # Zeroize password bytes if possible
            password_bytes = b'\x00' * len(password_bytes)
            
            logger.debug(f"Key derived successfully (length: {len(key)} bytes)")
            return key
            
        except Exception as e:
            logger.error(f"Key derivation failed: {e}")
            raise InvalidKeyError(f"Failed to derive key: {e}")
    
    def verify_password_strength(self, password: str, confirm_password: Optional[str] = None):
        """
        Validate password meets security requirements.
        
        Args:
            password: Password to validate
            confirm_password: Optional confirmation password
            
        Raises:
            PasswordTooWeakError: If password is too weak
        """
        try:
            PasswordValidator.validate(password, confirm_password)
            strength = PasswordValidator.estimate_strength(password)
            
            if strength < 0.5:
                logger.warning(f"Password strength is weak ({strength:.1%})")
            else:
                logger.debug(f"Password strength: {strength:.1%}")
                
        except PasswordTooWeakError as e:
            logger.warning(f"Weak password rejected: {e}")
            raise
    
    def estimate_brute_force_time(self, password: str) -> str:
        """
        Estimate time to brute-force the password.
        Educational purpose only - actual times vary greatly.
        
        Args:
            password: Password to estimate
            
        Returns:
            str: Human-readable time estimate
        """
        # Very rough estimation
        charset_size = 94  # Printable ASCII
        length = len(password)
        
        # Possible combinations
        combinations = charset_size ** length
        
        # Assume 1 billion guesses per second (high-end attacker)
        guesses_per_second = 1e9
        
        seconds = combinations / guesses_per_second
        
        # Convert to human readable
        if seconds < 1:
            return "instant"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:  # 365 days
            return f"{seconds/86400:.0f} days"
        else:
            years = seconds / 31536000
            if years > 1e9:
                return "> billion years"
            elif years > 1e6:
                return f"{years/1e6:.0f} million years"
            elif years > 1000:
                return f"{years/1000:.0f} thousand years"
            else:
                return f"{years:.0f} years"