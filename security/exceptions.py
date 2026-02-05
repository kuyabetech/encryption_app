"""
Security-related exceptions for controlled error handling.
"""

class SecurityException(Exception):
    """Base class for all security-related exceptions."""
    pass

class AuthenticationError(SecurityException):
    """Raised when MAC verification fails (tampering detected)."""
    pass

class DecryptionError(SecurityException):
    """Raised when decryption fails."""
    pass

class InvalidKeyError(SecurityException):
    """Raised when derived key is invalid."""
    pass

class InvalidMetadataError(SecurityException):
    """Raised when file metadata is corrupt or invalid."""
    pass

class PasswordTooWeakError(SecurityException):
    """Raised when password doesn't meet requirements."""
    pass

class VersionMismatchError(SecurityException):
    """Raised when encrypted file version is unsupported."""
    pass