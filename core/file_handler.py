"""
Safe file operations with atomic writes and error handling.
"""

import os
import tempfile
import shutil
from typing import Tuple, Optional
from pathlib import Path

from security.constants import MAX_FILE_SIZE
from security.exceptions import DecryptionError
from utils.logger import logger
from storage.metadata import MetadataHandler, FileMetadata


class FileHandler:
    """
    Handles file I/O operations with safety features:
    - Atomic writes (write to temp file, then rename)
    - Size validation
    - Backup creation
    - Secure deletion (optional)
    """
    
    @staticmethod
    def read_file(filepath: str) -> bytes:
        """
        Read file with safety checks.
        
        Args:
            filepath: Path to file
            
        Returns:
            bytes: File contents
            
        Raises:
            IOError: If file cannot be read
            ValueError: If file is too large
        """
        try:
            file_size = os.path.getsize(filepath)
            
            if file_size > MAX_FILE_SIZE:
                raise ValueError(
                    f"File too large ({file_size} bytes > {MAX_FILE_SIZE} bytes max)"
                )
            
            with open(filepath, 'rb') as f:
                content = f.read()
            
            logger.debug(f"Read {len(content)} bytes from {filepath}")
            return content
            
        except (IOError, OSError, PermissionError) as e:
            logger.error(f"Failed to read file {filepath}: {e}")
            raise
    
    @staticmethod
    def write_file_atomic(filepath: str, data: bytes, backup: bool = True) -> None:
        """
        Write file atomically to prevent corruption.
        
        Args:
            filepath: Destination path
            data: Data to write
            backup: Whether to create backup of existing file
            
        Raises:
            IOError: If write fails
        """
        filepath = Path(filepath)
        
        # Create backup if requested and file exists
        backup_path = None
        if backup and filepath.exists():
            backup_path = filepath.with_suffix(filepath.suffix + '.bak')
            try:
                shutil.copy2(filepath, backup_path)
                logger.debug(f"Created backup at {backup_path}")
            except Exception as e:
                logger.warning(f"Failed to create backup: {e}")
        
        # Write to temporary file
        temp_dir = filepath.parent
        with tempfile.NamedTemporaryFile(
            mode='wb',
            dir=temp_dir,
            delete=False,
            prefix='.tmp_',
            suffix=filepath.suffix
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            tmp_file.write(data)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        
        try:
            # Atomic rename (POSIX)
            os.replace(tmp_path, filepath)
            logger.debug(f"Atomically wrote {len(data)} bytes to {filepath}")
            
            # Clean up backup after successful write
            if backup_path and backup_path.exists():
                try:
                    os.remove(backup_path)
                    logger.debug(f"Removed backup {backup_path}")
                except Exception as e:
                    logger.warning(f"Failed to remove backup: {e}")
                    
        except Exception as e:
            # Clean up temp file on error
            try:
                if tmp_path.exists():
                    os.remove(tmp_path)
            except Exception:
                pass
            
            logger.error(f"Atomic write failed for {filepath}: {e}")
            
            # Restore from backup if available
            if backup_path and backup_path.exists():
                try:
                    shutil.copy2(backup_path, filepath)
                    logger.info(f"Restored from backup {backup_path}")
                except Exception as restore_error:
                    logger.error(f"Failed to restore from backup: {restore_error}")
            
            raise
    
    @staticmethod
    def read_encrypted_file(filepath: str) -> Tuple[FileMetadata, bytes]:
        """
        Read and parse encrypted file.
        
        Args:
            filepath: Path to encrypted file
            
        Returns:
            Tuple[FileMetadata, bytes]: Metadata and ciphertext
            
        Raises:
            InvalidMetadataError: If file is not a valid encrypted file
        """
        encrypted_data = FileHandler.read_file(filepath)
        return MetadataHandler.parse(encrypted_data)
    
    @staticmethod
    def write_encrypted_file(filepath: str, metadata: FileMetadata, ciphertext: bytes) -> None:
        """
        Write encrypted file with metadata.
        
        Args:
            filepath: Destination path
            metadata: File metadata
            ciphertext: Encrypted data
        """
        encrypted_data = MetadataHandler.serialize(metadata, ciphertext)
        FileHandler.write_file_atomic(filepath, encrypted_data)
    
    @staticmethod
    def get_output_filename(input_path: str, operation: str, suffix: str = None) -> str:
        """
        Generate output filename for encryption/decryption.
        
        Args:
            input_path: Input file path
            operation: 'encrypt' or 'decrypt'
            suffix: Custom suffix (optional)
            
        Returns:
            str: Output file path
        """
        path = Path(input_path)
        
        if suffix:
            new_suffix = suffix
        elif operation == 'encrypt':
            new_suffix = '.enc'
        elif operation == 'decrypt':
            # Remove .enc or add .decrypted
            if path.suffix == '.enc':
                new_suffix = path.stem.rsplit('.', 1)[-1] if '.' in path.stem else ''
            else:
                new_suffix = '.decrypted'
        else:
            new_suffix = f'.{operation}'
        
        if new_suffix and not new_suffix.startswith('.'):
            new_suffix = '.' + new_suffix
        
        output_name = path.stem + new_suffix
        
        # Avoid overwriting
        counter = 1
        original_output = output_name
        while (path.parent / output_name).exists():
            output_name = f"{original_output}.{counter}"
            counter += 1
        
        return str(path.parent / output_name)
    
    @staticmethod
    def secure_delete(filepath: str, passes: int = 3) -> bool:
        """
        Securely delete file by overwriting before deletion.
        WARNING: Not effective on SSDs with wear leveling.
        
        Args:
            filepath: Path to file
            passes: Number of overwrite passes
            
        Returns:
            bool: True if successful
        """
        try:
            if not os.path.exists(filepath):
                return True
            
            file_size = os.path.getsize(filepath)
            
            # Overwrite with random data multiple times
            with open(filepath, 'wb') as f:
                for i in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Delete the file
            os.remove(filepath)
            
            # Overwrite the filename in directory (not really possible in Python)
            logger.info(f"Securely deleted {filepath} ({passes} passes)")
            return True
            
        except Exception as e:
            logger.error(f"Secure delete failed for {filepath}: {e}")
            # Fall back to normal delete
            try:
                os.remove(filepath)
                return True
            except:
                return False
    
    @staticmethod
    def cleanup_temp_files(directory: str = None):
        """
        Clean up temporary files created by the application.
        
        Args:
            directory: Directory to clean (default: current directory)
        """
        if directory is None:
            directory = '.'
        
        dir_path = Path(directory)
        temp_files = list(dir_path.glob('.tmp_*'))
        
        for temp_file in temp_files:
            try:
                if temp_file.is_file():
                    os.remove(temp_file)
                    logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                logger.warning(f"Failed to clean up {temp_file}: {e}")