#!/usr/bin/env python3
"""
Secure File Encryption CLI
Password-based AES-256-GCM file encryption with Argon2 key derivation.
"""

import sys
import getpass
import argparse
import traceback
from pathlib import Path
from typing import Optional

# Add project modules to path
sys.path.insert(0, str(Path(__file__).parent))

from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.file_handler import FileHandler
from security.exceptions import (
    AuthenticationError, DecryptionError, InvalidKeyError,
    PasswordTooWeakError, InvalidMetadataError, VersionMismatchError
)
from utils.validators import PasswordValidator, FileValidator
from utils.logger import logger
from storage.metadata import FileMetadata


class SecureEncryptCLI:
    """Command-line interface for secure file encryption."""
    
    def __init__(self):
        """Initialize CLI with key manager."""
        self.key_manager = KeyManager()
        self.encrypted_ext = '.enc'
    
    def get_password(self, confirm: bool = False, operation: str = None) -> str:
        """
        Securely get password from user.
        
        Args:
            confirm: Whether to ask for confirmation
            operation: 'encrypt' or 'decrypt' for context
            
        Returns:
            str: Password entered by user
        """
        prompt = "Enter password"
        if operation:
            prompt += f" for {operation}"
        prompt += ": "
        
        while True:
            try:
                password = getpass.getpass(prompt)
                
                if not password:
                    print("❌ Password cannot be empty")
                    continue
                
                if confirm:
                    confirm_prompt = "Confirm password: "
                    password_confirm = getpass.getpass(confirm_prompt)
                    
                    if password != password_confirm:
                        print("❌ Passwords do not match")
                        continue
                    
                    # Validate password strength
                    self.key_manager.verify_password_strength(password, password_confirm)
                else:
                    # Still validate basic requirements
                    self.key_manager.verify_password_strength(password)
                
                # Estimate strength
                strength = PasswordValidator.estimate_strength(password)
                if strength < 0.5:
                    print(f"⚠️  Password strength: {strength:.0%} - consider using a stronger password")
                else:
                    print(f"✅ Password strength: {strength:.0%}")
                
                return password
                
            except PasswordTooWeakError as e:
                print(f"❌ {e}")
                if not confirm:
                    # For decryption, we still need to try
                    retry = input("Use anyway? (y/N): ").lower().strip()
                    if retry == 'y':
                        return password
            except KeyboardInterrupt:
                print("\n⏹️  Operation cancelled")
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error: {e}")
                sys.exit(1)
    
    def encrypt_file(self, input_file: str, output_file: Optional[str] = None) -> bool:
        """
        Encrypt a file.
        
        Args:
            input_file: Path to file to encrypt
            output_file: Output path (optional)
            
        Returns:
            bool: True if successful
        """
        try:
            # Validate input file
            is_valid, message = FileValidator.is_safe_to_encrypt(input_file)
            if not is_valid:
                print(f"❌ {message}")
                return False
            
            # Get password
            print(f"\n🔐 Encrypting: {Path(input_file).name}")
            password = self.get_password(confirm=True, operation='encryption')
            
            # Generate output filename
            if not output_file:
                output_file = FileHandler.get_output_filename(input_file, 'encrypt', self.encrypted_ext)
            
            # Check if output file already exists
            if Path(output_file).exists():
                overwrite = input(f"⚠️  {output_file} already exists. Overwrite? (y/N): ").lower().strip()
                if overwrite != 'y':
                    print("⏹️  Operation cancelled")
                    return False
            
            # Generate salt and derive key
            print("⏳ Deriving encryption key...")
            salt = self.key_manager.generate_salt()
            key = self.key_manager.derive_key(password, salt)
            
            # Read file
            print("📖 Reading file...")
            plaintext = FileHandler.read_file(input_file)
            
            # Encrypt
            print("🔒 Encrypting...")
            nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
            
            # Create metadata
            metadata = FileMetadata.create_new(salt, nonce, tag)
            
            # Write encrypted file
            print(f"💾 Writing encrypted file: {Path(output_file).name}")
            FileHandler.write_encrypted_file(output_file, metadata, ciphertext)
            
            # Clear sensitive data from memory
            key = b'\x00' * len(key)
            password = ' ' * len(password)
            
            print(f"\n✅ Successfully encrypted to: {output_file}")
            print(f"   Original size: {len(plaintext):,} bytes")
            print(f"   Encrypted size: {len(ciphertext) + 100:,} bytes")  # Approximate
            
            # Offer to securely delete original
            if input("\n🗑️  Securely delete original file? (y/N): ").lower().strip() == 'y':
                if FileHandler.secure_delete(input_file):
                    print("✅ Original file securely deleted")
                else:
                    print("⚠️  Could not securely delete (falling back to normal delete)")
                    try:
                        Path(input_file).unlink()
                        print("✅ Original file deleted")
                    except:
                        print("❌ Failed to delete original file")
            
            return True
            
        except (InvalidKeyError, DecryptionError) as e:
            print(f"❌ Encryption failed: {e}")
            logger.error(f"Encryption failed: {e}", exc_info=True)
            return False
        except KeyboardInterrupt:
            print("\n⏹️  Operation cancelled")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            logger.error(f"Unexpected error: {e}", exc_info=True)
            traceback.print_exc()
            return False
    
    def decrypt_file(self, input_file: str, output_file: Optional[str] = None) -> bool:
        """
        Decrypt a file.
        
        Args:
            input_file: Path to encrypted file
            output_file: Output path (optional)
            
        Returns:
            bool: True if successful
        """
        try:
            # Validate input file
            if not Path(input_file).exists():
                print(f"❌ File not found: {input_file}")
                return False
            
            # Check if file looks encrypted
            if not input_file.endswith(self.encrypted_ext):
                print(f"⚠️  File doesn't have .enc extension. Continue anyway? (y/N): ", end='')
                if input().lower().strip() != 'y':
                    return False
            
            # Get password
            print(f"\n🔓 Decrypting: {Path(input_file).name}")
            password = self.get_password(operation='decryption')
            
            # Read and parse encrypted file
            print("📖 Reading encrypted file...")
            metadata, ciphertext = FileHandler.read_encrypted_file(input_file)
            
            # Derive key using stored salt
            print("⏳ Deriving decryption key...")
            key = self.key_manager.derive_key(password, metadata.salt)
            
            # Decrypt
            print("🔓 Decrypting...")
            plaintext = CryptoEngine.decrypt(
                key, metadata.nonce, ciphertext, metadata.tag
            )
            
            # Generate output filename
            if not output_file:
                output_file = FileHandler.get_output_filename(input_file, 'decrypt')
            
            # Check if output file already exists
            if Path(output_file).exists():
                overwrite = input(f"⚠️  {output_file} already exists. Overwrite? (y/N): ").lower().strip()
                if overwrite != 'y':
                    print("⏹️  Operation cancelled")
                    return False
            
            # Write decrypted file
            print(f"💾 Writing decrypted file: {Path(output_file).name}")
            FileHandler.write_file_atomic(output_file, plaintext, backup=False)
            
            # Clear sensitive data
            key = b'\x00' * len(key)
            password = ' ' * len(password)
            plaintext = b'\x00' * len(plaintext)
            
            print(f"\n✅ Successfully decrypted to: {output_file}")
            print(f"   File size: {len(plaintext):,} bytes")
            
            return True
            
        except AuthenticationError as e:
            print(f"\n❌❌❌ SECURITY ALERT: {e}")
            print("   The file may have been tampered with or the password is incorrect.")
            print("   Do NOT trust the contents of this file!")
            logger.critical(f"Authentication failed for {input_file}")
            return False
        except (InvalidMetadataError, VersionMismatchError) as e:
            print(f"❌ Invalid encrypted file: {e}")
            print("   This might not be a valid encrypted file or was created with a different version.")
            return False
        except (InvalidKeyError, DecryptionError) as e:
            print(f"❌ Decryption failed: {e}")
            print("   Wrong password or corrupted file.")
            return False
        except KeyboardInterrupt:
            print("\n⏹️  Operation cancelled")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return False
    
    def show_info(self, file_path: str):
        """
        Show information about an encrypted file.
        
        Args:
            file_path: Path to encrypted file
        """
        try:
            if not Path(file_path).exists():
                print(f"❌ File not found: {file_path}")
                return
            
            print(f"\n📊 File Information: {Path(file_path).name}")
            print("=" * 50)
            
            # Read metadata
            metadata, ciphertext = FileHandler.read_encrypted_file(file_path)
            
            print(f"Version:        {metadata.version}")
            print(f"Algorithm:      {'AES-256-GCM' if metadata.algorithm == 1 else 'Unknown'}")
            print(f"Salt:           {metadata.salt.hex()[:16]}...")
            print(f"Nonce:          {metadata.nonce.hex()[:16]}...")
            print(f"Tag:            {metadata.tag.hex()[:16]}...")
            print(f"KDF:            {metadata.kdf_params.get('algorithm', 'unknown')}")
            print(f"Ciphertext size: {len(ciphertext):,} bytes")
            print(f"Total size:     {Path(file_path).stat().st_size:,} bytes")
            
            # Check if password is needed
            if input("\n🔍 Test password? (y/N): ").lower().strip() == 'y':
                password = getpass.getpass("Enter password to test: ")
                try:
                    key = self.key_manager.derive_key(password, metadata.salt)
                    print("✅ Key derived successfully (password may be correct)")
                    key = b'\x00' * len(key)
                except:
                    print("❌ Failed to derive key (likely wrong password)")
            
        except InvalidMetadataError:
            print("❌ This does not appear to be a valid encrypted file")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def benchmark(self):
        """Run performance and security benchmark."""
        print("\n🏃 Running benchmarks...")
        print("=" * 50)
        
        # Test key derivation speed
        test_password = "TestPassword123!"
        test_salt = self.key_manager.generate_salt()
        
        import time
        start = time.time()
        key = self.key_manager.derive_key(test_password, test_salt)
        elapsed = time.time() - start
        
        print(f"Key derivation time: {elapsed:.3f}s")
        print(f"Key length: {len(key)} bytes")
        
        # Test encryption/decryption speed
        test_data = os.urandom(1024 * 1024)  # 1MB
        
        start = time.time()
        nonce, ciphertext, tag = CryptoEngine.encrypt(key, test_data)
        encrypt_time = time.time() - start
        
        start = time.time()
        plaintext = CryptoEngine.decrypt(key, nonce, ciphertext, tag)
        decrypt_time = time.time() - start
        
        print(f"Encryption speed: {len(test_data) / encrypt_time / 1024 / 1024:.2f} MB/s")
        print(f"Decryption speed: {len(test_data) / decrypt_time / 1024 / 1024:.2f} MB/s")
        
        # Verify
        if test_data == plaintext:
            print("✅ Encryption/decryption verified")
        else:
            print("❌ Verification failed!")
        
        # Clean up
        key = b'\x00' * len(key)
    
    def interactive_mode(self):
        """Run in interactive mode."""
        print("\n" + "=" * 50)
        print("🔐 Secure File Encryption - Interactive Mode")
        print("=" * 50)
        
        while True:
            print("\nOptions:")
            print("  1. Encrypt a file")
            print("  2. Decrypt a file")
            print("  3. View file info")
            print("  4. Run benchmark")
            print("  5. Exit")
            
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == '1':
                file_path = input("Enter file path to encrypt: ").strip()
                if file_path:
                    self.encrypt_file(file_path)
            elif choice == '2':
                file_path = input("Enter file path to decrypt: ").strip()
                if file_path:
                    self.decrypt_file(file_path)
            elif choice == '3':
                file_path = input("Enter encrypted file path: ").strip()
                if file_path:
                    self.show_info(file_path)
            elif choice == '4':
                self.benchmark()
            elif choice == '5':
                print("\n👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice")
    
    def run(self):
        """Main CLI entry point."""
        parser = argparse.ArgumentParser(
            description='Secure File Encryption with AES-256-GCM and Argon2',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s encrypt document.pdf
  %(prog)s decrypt document.enc -o document_decrypted.pdf
  %(prog)s info document.enc
  %(prog)s interactive
  %(prog)s benchmark
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Encrypt command
        encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
        encrypt_parser.add_argument('input', help='Input file to encrypt')
        encrypt_parser.add_argument('-o', '--output', help='Output file (default: input.enc)')
        
        # Decrypt command
        decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
        decrypt_parser.add_argument('input', help='Encrypted file to decrypt')
        decrypt_parser.add_argument('-o', '--output', help='Output file')
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Show info about encrypted file')
        info_parser.add_argument('input', help='Encrypted file to inspect')
        
        # Benchmark command
        subparsers.add_parser('benchmark', help='Run performance benchmark')
        
        # Interactive mode
        subparsers.add_parser('interactive', help='Start interactive mode')
        
        # Version
        parser.add_argument('--version', action='store_true', help='Show version')
        
        args = parser.parse_args()
        
        # Show version
        if args.version:
            print("Secure File Encryption v1.0.0")
            print("AES-256-GCM with Argon2 key derivation")
            return
        
        # No command provided
        if not args.command:
            parser.print_help()
            return
        
        # Execute command
        try:
            if args.command == 'encrypt':
                self.encrypt_file(args.input, args.output)
            elif args.command == 'decrypt':
                self.decrypt_file(args.input, args.output)
            elif args.command == 'info':
                self.show_info(args.input)
            elif args.command == 'benchmark':
                self.benchmark()
            elif args.command == 'interactive':
                self.interactive_mode()
                
        except KeyboardInterrupt:
            print("\n\n⏹️  Operation cancelled by user")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Fatal error: {e}")
            logger.critical(f"Fatal error: {e}", exc_info=True)
            sys.exit(1)


def main():
    """Main entry point."""
    # Clean up any leftover temp files
    FileHandler.cleanup_temp_files()
    
    # Run CLI
    cli = SecureEncryptCLI()
    cli.run()
    
    # Final cleanup
    FileHandler.cleanup_temp_files()


if __name__ == '__main__':
    main()