"""
Encrypted file format specification and metadata handling.
"""

import struct
from dataclasses import dataclass
from typing import Optional, Tuple
from security.constants import (
    MAGIC_HEADER, CURRENT_VERSION, AES_NONCE_SIZE,
    SALT_SIZE, AES_TAG_SIZE, ALGORITHM_AES256_GCM
)
from security.exceptions import InvalidMetadataError, VersionMismatchError


@dataclass
class FileMetadata:
    """Metadata stored with encrypted files."""
    version: int
    algorithm: int
    salt: bytes
    nonce: bytes
    tag: bytes
    kdf_params: Optional[dict] = None
    
    @classmethod
    def create_new(cls, salt: bytes, nonce: bytes, tag: bytes) -> 'FileMetadata':
        """Create metadata for a new encryption operation."""
        return cls(
            version=CURRENT_VERSION,
            algorithm=ALGORITHM_AES256_GCM,
            salt=salt,
            nonce=nonce,
            tag=tag,
            kdf_params={
                'algorithm': 'argon2id',
                'time_cost': 2,
                'memory_cost': 64 * 1024,
                'parallelism': 1
            }
        )


class MetadataHandler:
    """Handles serialization and deserialization of encrypted file metadata."""
    
    # Binary format structure:
    # | MAGIC (5B) | VERSION (1B) | ALGORITHM (1B) | SALT_LEN (1B) | SALT (16B) |
    # | NONCE_LEN (1B) | NONCE (12B) | TAG_LEN (1B) | TAG (16B) | KDF_PARAMS_LEN (2B) | KDF_PARAMS (var) |
    # | CIPHERTEXT_LEN (8B) | CIPHERTEXT (var) |
    
    MAGIC = MAGIC_HEADER
    HEADER_FORMAT = '!5sBB'  # magic, version, algorithm
    
    @staticmethod
    def serialize(metadata: FileMetadata, ciphertext: bytes) -> bytes:
        """
        Serialize metadata and ciphertext into encrypted file format.
        
        Args:
            metadata: File metadata
            ciphertext: Encrypted data
            
        Returns:
            bytes: Complete encrypted file bytes
        """
        # Serialize KDF params as simple binary (JSON in production)
        kdf_params = b'argon2id'  # Simplified for now
        
        # Build parts
        parts = [
            MAGIC_HEADER,
            bytes([metadata.version]),
            bytes([metadata.algorithm]),
            bytes([len(metadata.salt)]),
            metadata.salt,
            bytes([len(metadata.nonce)]),
            metadata.nonce,
            bytes([len(metadata.tag)]),
            metadata.tag,
            len(kdf_params).to_bytes(2, 'big'),
            kdf_params,
            len(ciphertext).to_bytes(8, 'big'),
            ciphertext
        ]
        
        return b''.join(parts)
    
    @staticmethod
    def parse(encrypted_data: bytes) -> Tuple[FileMetadata, bytes]:
        """
        Parse encrypted file format into metadata and ciphertext.
        
        Args:
            encrypted_data: Complete encrypted file bytes
            
        Returns:
            Tuple[FileMetadata, bytes]: Metadata and ciphertext
            
        Raises:
            InvalidMetadataError: If data is corrupt
            VersionMismatchError: If version is unsupported
        """
        try:
            offset = 0
            
            # Parse fixed header
            if len(encrypted_data) < len(MAGIC_HEADER) + 3:
                raise InvalidMetadataError("File too short to contain valid header")
            
            magic = encrypted_data[offset:offset+5]
            offset += 5
            
            if magic != MAGIC_HEADER:
                raise InvalidMetadataError("Invalid magic header (not an encrypted file?)")
            
            version = encrypted_data[offset]
            offset += 1
            
            if version > CURRENT_VERSION:
                raise VersionMismatchError(
                    f"File version {version} is newer than supported {CURRENT_VERSION}"
                )
            
            algorithm = encrypted_data[offset]
            offset += 1
            
            # Parse salt
            salt_len = encrypted_data[offset]
            offset += 1
            salt = encrypted_data[offset:offset+salt_len]
            offset += salt_len
            
            # Parse nonce
            nonce_len = encrypted_data[offset]
            offset += 1
            nonce = encrypted_data[offset:offset+nonce_len]
            offset += nonce_len
            
            # Parse tag
            tag_len = encrypted_data[offset]
            offset += 1
            tag = encrypted_data[offset:offset+tag_len]
            offset += tag_len
            
            # Parse KDF params (simplified)
            kdf_params_len = int.from_bytes(encrypted_data[offset:offset+2], 'big')
            offset += 2
            kdf_params = encrypted_data[offset:offset+kdf_params_len]
            offset += kdf_params_len
            
            # Parse ciphertext
            ciphertext_len = int.from_bytes(encrypted_data[offset:offset+8], 'big')
            offset += 8
            ciphertext = encrypted_data[offset:offset+ciphertext_len]
            
            # Validate lengths
            if len(ciphertext) != ciphertext_len:
                raise InvalidMetadataError("Ciphertext length mismatch")
            
            metadata = FileMetadata(
                version=version,
                algorithm=algorithm,
                salt=salt,
                nonce=nonce,
                tag=tag,
                kdf_params={'algorithm': kdf_params.decode()}  # Simplified
            )
            
            return metadata, ciphertext
            
        except (IndexError, struct.error) as e:
            raise InvalidMetadataError(f"Failed to parse metadata: {e}")