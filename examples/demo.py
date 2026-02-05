#!/usr/bin/env python3
"""
Demonstration of the encryption system.
"""

import os
import tempfile
from pathlib import Path

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.file_handler import FileHandler
from utils.validators import PasswordValidator


def demo_basic_encryption():
    """Demonstrate basic encryption/decryption."""
    print("🔐 Basic Encryption Demo")
    print("=" * 50)
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        test_file = f.name
        f.write("This is a secret message!\n" * 100)
    
    print(f"Created test file: {test_file}")
    print(f"File size: {os.path.getsize(test_file)} bytes")
    
    # Create key manager
    km = KeyManager()
    
    # Test password
    password = "MySuperStrongPassword123!"
    
    # Validate password
    try:
        is_valid, msg = PasswordValidator.validate(password)
        print(f"Password validation: {msg}")
    except Exception as e:
        print(f"Password validation failed: {e}")
    
    # Generate salt and derive key
    salt = km.generate_salt()
    key = km.derive_key(password, salt)
    
    print(f"Salt: {salt.hex()[:16]}...")
    print(f"Key: {key.hex()[:16]}...")
    
    # Read file
    plaintext = FileHandler.read_file(test_file)
    
    # Encrypt
    nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
    
    print(f"\nEncryption successful:")
    print(f"  Nonce: {nonce.hex()[:16]}...")
    print(f"  Tag: {tag.hex()[:16]}...")
    print(f"  Ciphertext size: {len(ciphertext)} bytes")
    
    # Decrypt
    decrypted = CryptoEngine.decrypt(key, nonce, ciphertext, tag)
    
    if decrypted == plaintext:
        print("✅ Decryption successful - data matches!")
    else:
        print("❌ Decryption failed - data mismatch!")
    
    # Clean up
    os.unlink(test_file)
    
    # Zeroize sensitive data
    key = b'\x00' * len(key)
    password = ' ' * len(password)
    
    print("\n" + "=" * 50)


def demo_password_strength():
    """Demonstrate password strength estimation."""
    print("\n🔑 Password Strength Demo")
    print("=" * 50)
    
    test_passwords = [
        "password",
        "123456",
        "Password123",
        "MySuperStrongPassword123!",
        "correct horse battery staple",
        "Tr0ub4dor&3",
    ]
    
    for pwd in test_passwords:
        try:
            is_valid, msg = PasswordValidator.validate(pwd)
            strength = PasswordValidator.estimate_strength(pwd)
            
            print(f"\nPassword: {pwd[:20]:20} | Strength: {strength:.0%}")
            print(f"  Validation: {msg}")
            
            km = KeyManager()
            estimate = km.estimate_brute_force_time(pwd)
            print(f"  Brute-force estimate: {estimate}")
            
        except Exception as e:
            print(f"\nPassword: {pwd[:20]:20} | ❌ {e}")
    
    print("\n" + "=" * 50)


def demo_file_operations():
    """Demonstrate file operations."""
    print("\n📁 File Operations Demo")
    print("=" * 50)
    
    # Create test files
    test_dir = tempfile.mkdtemp()
    test_file = Path(test_dir) / "test.txt"
    encrypted_file = Path(test_dir) / "test.enc"
    decrypted_file = Path(test_dir) / "test_decrypted.txt"
    
    # Write test data
    with open(test_file, 'w') as f:
        f.write("Confidential data: " + "x" * 1000)
    
    print(f"Test directory: {test_dir}")
    print(f"Original file: {test_file}")
    
    # Read file
    data = FileHandler.read_file(str(test_file))
    print(f"Read {len(data)} bytes")
    
    # Atomic write
    FileHandler.write_file_atomic(str(test_file) + ".backup", data)
    print("Created atomic backup")
    
    # Generate output names
    enc_name = FileHandler.get_output_filename(str(test_file), 'encrypt')
    print(f"Encryption output would be: {enc_name}")
    
    # Clean up
    import shutil
    shutil.rmtree(test_dir)
    print("Cleaned up test directory")
    
    print("\n" + "=" * 50)


def main():
    """Run all demos."""
    print("🚀 Secure Encryption System Demo")
    print("=" * 50)
    
    demo_basic_encryption()
    demo_password_strength()
    demo_file_operations()
    
    print("\n🎉 Demo complete!")
    print("\nTo use the full CLI:")
    print("  python app.py encrypt myfile.txt")
    print("  python app.py decrypt myfile.enc")
    print("  python app.py interactive")


if __name__ == "__main__":
    main()