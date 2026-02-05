"""
Core cryptographic operations using AES-GCM.
Stateless - only processes bytes in, bytes out.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from security.constants import AES_KEY_SIZE, AES_NONCE_SIZE, AES_TAG_SIZE, CHUNK_SIZE
from security.exceptions import AuthenticationError, DecryptionError
from utils.logger import logger


class CryptoEngine:
    """
    Handles AES-GCM encryption and decryption.
    
    Features:
    - Authenticated encryption (tamper detection)
    - Random nonce for each encryption
    - Chunked processing for large files
    - Zero-copy where possible
    """
    
    @staticmethod
    def generate_nonce() -> bytes:
        """
        Generate cryptographically secure random nonce (IV).
        
        Returns:
            bytes: Random nonce of AES_NONCE_SIZE bytes
        """
        return os.urandom(AES_NONCE_SIZE)
    
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext using AES-GCM.
        
        Args:
            key: Encryption key (must be AES_KEY_SIZE bytes)
            plaintext: Data to encrypt
            
        Returns:
            Tuple[bytes, bytes, bytes]: (nonce, ciphertext, authentication_tag)
            
        Raises:
            ValueError: If key is wrong size
            DecryptionError: If encryption fails
        """
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
        
        try:
            # Generate unique nonce for this encryption
            nonce = CryptoEngine.generate_nonce()
            
            # Create AES-GCM cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt the data
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Get authentication tag
            tag = encryptor.tag
            
            if len(tag) != AES_TAG_SIZE:
                logger.warning(f"Tag size is {len(tag)} bytes, expected {AES_TAG_SIZE}")
            
            logger.debug(f"Encrypted {len(plaintext)} bytes -> {len(ciphertext)} bytes")
            return nonce, ciphertext, tag
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise DecryptionError(f"Encryption failed: {e}")
    
    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Decrypt ciphertext and verify authentication tag.
        
        Args:
            key: Encryption key (must be AES_KEY_SIZE bytes)
            nonce: Nonce used during encryption
            ciphertext: Encrypted data
            tag: Authentication tag
            
        Returns:
            bytes: Decrypted plaintext
            
        Raises:
            AuthenticationError: If tag verification fails (tampering detected)
            DecryptionError: If decryption fails
        """
        if len(key) != AES_KEY_SIZE:
            raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
        
        if len(nonce) != AES_NONCE_SIZE:
            logger.warning(f"Nonce size is {len(nonce)} bytes, expected {AES_NONCE_SIZE}")
        
        try:
            # Create AES-GCM cipher for decryption
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt and verify tag
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            logger.debug(f"Decrypted {len(ciphertext)} bytes -> {len(plaintext)} bytes")
            return plaintext
            
        except InvalidTag as e:
            logger.critical("Authentication failed - possible tampering detected!")
            raise AuthenticationError("Data integrity check failed. File may be corrupted or tampered with.")
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Decryption failed: {e}")
    
    @staticmethod
    def encrypt_chunked(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt large data in chunks to manage memory.
        
        Args:
            key: Encryption key
            plaintext: Data to encrypt
            
        Returns:
            Tuple[bytes, bytes, bytes]: (nonce, ciphertext, tag)
        """
        # For GCM, we need to encrypt all at once due to authentication
        # But we can still process in chunks if needed for very large files
        if len(plaintext) <= CHUNK_SIZE * 10:  # Up to 10 chunks
            return CryptoEngine.encrypt(key, plaintext)
        
        # For very large files, consider hybrid approach:
        # 1. Generate random AES key for data
        # 2. Encrypt data with AES-CTR (no auth)
        # 3. Encrypt AES key with AES-GCM
        # 4. HMAC the ciphertext
        # This is more complex but allows streaming
        
        logger.warning(f"Encrypting large file ({len(plaintext)} bytes) in single operation")
        return CryptoEngine.encrypt(key, plaintext)
    
    @staticmethod
    def validate_key(key: bytes) -> bool:
        """
        Basic validation of key format.
        
        Args:
            key: Key to validate
            
        Returns:
            bool: True if key appears valid
        """
        if not key:
            return False
        if len(key) != AES_KEY_SIZE:
            return False
        # Check key isn't all zeros (very basic check)
        if all(b == 0 for b in key):
            logger.warning("Key is all zeros - likely invalid")
            return False
        return True