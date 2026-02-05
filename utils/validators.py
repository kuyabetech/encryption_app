"""
Password and input validation utilities.
"""

import re
from typing import Tuple, Optional
from security.constants import MIN_PASSWORD_LENGTH
from security.exceptions import PasswordTooWeakError


class PasswordValidator:
    """Validates password strength."""
    
    # Common weak passwords to reject
    COMMON_PASSWORDS = {
        'password', '123456', 'qwerty', 'letmein', 'welcome',
        'admin', 'password123', '123456789', '12345678', '12345'
    }
    
    @staticmethod
    def validate(password: str, confirm_password: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            confirm_password: Optional confirmation password
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
            
        Raises:
            PasswordTooWeakError: If password doesn't meet requirements
        """
        errors = []
        
        # Check length
        if len(password) < MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        
        # Check for common passwords
        if password.lower() in PasswordValidator.COMMON_PASSWORDS:
            errors.append("Password is too common")
        
        # Check character variety (optional but recommended)
        if not any(c.isupper() for c in password):
            errors.append("Add at least one uppercase letter")
        if not any(c.islower() for c in password):
            errors.append("Add at least one lowercase letter")
        if not any(c.isdigit() for c in password):
            errors.append("Add at least one number")
        
        # Check confirmation
        if confirm_password is not None and password != confirm_password:
            errors.append("Passwords do not match")
        
        if errors:
            error_msg = "; ".join(errors)
            raise PasswordTooWeakError(error_msg)
        
        return True, "Password is strong enough"
    
    @staticmethod
    def estimate_strength(password: str) -> float:
        """
        Estimate password strength (0.0 to 1.0).
        
        Args:
            password: Password to evaluate
            
        Returns:
            float: Strength score between 0.0 and 1.0
        """
        score = 0.0
        
        # Length contribution (max 0.4)
        length_score = min(len(password) / 30, 1.0) * 0.4
        score += length_score
        
        # Character variety (max 0.3)
        variety_bonus = 0.0
        if any(c.isupper() for c in password):
            variety_bonus += 0.075
        if any(c.islower() for c in password):
            variety_bonus += 0.075
        if any(c.isdigit() for c in password):
            variety_bonus += 0.075
        if any(not c.isalnum() for c in password):
            variety_bonus += 0.075
        score += min(variety_bonus, 0.3)
        
        # Entropy estimation (max 0.3)
        # Simple character set estimation
        char_set_size = 0
        if any(c.islower() for c in password):
            char_set_size += 26
        if any(c.isupper() for c in password):
            char_set_size += 26
        if any(c.isdigit() for c in password):
            char_set_size += 10
        if any(not c.isalnum() for c in password):
            char_set_size += 32
        
        if char_set_size > 0:
            entropy = len(password) * (char_set_size.bit_length() / 8)
            entropy_score = min(entropy / 100, 1.0) * 0.3
            score += entropy_score
        
        return min(score, 1.0)


class FileValidator:
    """Validates files for encryption/decryption."""
    
    @staticmethod
    def is_safe_to_encrypt(filepath: str) -> Tuple[bool, str]:
        """
        Check if a file is safe to encrypt.
        
        Args:
            filepath: Path to the file
            
        Returns:
            Tuple[bool, str]: (is_safe, error_message)
        """
        import os
        
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                return False, "File does not exist"
            
            # Check if it's a file
            if not os.path.isfile(filepath):
                return False, "Path is not a regular file"
            
            # Check file size
            file_size = os.path.getsize(filepath)
            from security.constants import MAX_FILE_SIZE
            if file_size > MAX_FILE_SIZE:
                return False, f"File too large (max {MAX_FILE_SIZE / (1024**3):.1f} GB)"
            
            # Check if readable
            if not os.access(filepath, os.R_OK):
                return False, "File is not readable"
            
            return True, "File is valid"
            
        except (OSError, PermissionError) as e:
            return False, f"Access error: {e}"