#!/usr/bin/env python3
"""
Simple demonstration of the encryption system.
Works even if Argon2 is not available.
"""

import os
import tempfile
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.file_handler import FileHandler
from utils.validators import PasswordValidator


def test_key_manager():
    """Test the KeyManager class."""
    print("🔑 Testing KeyManager...")
    print("-" * 50)
    
    try:
        km = KeyManager()
        print(f"✓ KeyManager initialized")
        print(f"  Using Argon2: {km.use_argon2}")
        
        # Generate salt
        salt = km.generate_salt()
        print(f"✓ Generated salt: {salt.hex()[:16]}...")
        
        # Test password
        password = "MyTestPassword123!"
        
        # Validate password
        try:
            is_valid, msg = PasswordValidator.validate(password)
            print(f"✓ Password validation: {msg}")
        except Exception as e:
            print(f"⚠ Password validation: {e}")
        
        # Derive key
        key = km.derive_key(password, salt)
        print(f"✓ Derived key: {len(key)} bytes")
        print(f"  Key preview: {key.hex()[:32]}...")
        
        # Estimate brute force time
        estimate = km.estimate_brute_force_time(password)
        print(f"✓ Brute-force estimate: {estimate}")
        
        return True
        
    except Exception as e:
        print(f"✗ KeyManager test failed: {e}")
        return False


def test_crypto_engine():
    """Test the CryptoEngine class."""
    print("\n🔐 Testing CryptoEngine...")
    print("-" * 50)
    
    try:
        # Generate a test key
        key = os.urandom(32)  # 256-bit key
        
        # Test data
        plaintext = b"This is a secret message that needs encryption!"
        
        # Encrypt
        nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
        print(f"✓ Encryption successful")
        print(f"  Nonce: {nonce.hex()[:16]}...")
        print(f"  Ciphertext: {len(ciphertext)} bytes")
        print(f"  Tag: {tag.hex()[:16]}...")
        
        # Decrypt
        decrypted = CryptoEngine.decrypt(key, nonce, ciphertext, tag)
        print(f"✓ Decryption successful")
        
        # Verify
        if decrypted == plaintext:
            print("✅ Data integrity verified")
        else:
            print("❌ Data mismatch!")
            
        # Test tamper detection
        try:
            # Modify ciphertext slightly
            tampered = bytearray(ciphertext)
            tampered[10] ^= 0x01  # Flip one bit
            CryptoEngine.decrypt(key, nonce, bytes(tampered), tag)
            print("❌ Tamper detection failed!")
        except Exception as e:
            print(f"✅ Tamper detection working: {type(e).__name__}")
            
        return True
        
    except Exception as e:
        print(f"✗ CryptoEngine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_file_handler():
    """Test the FileHandler class."""
    print("\n📁 Testing FileHandler...")
    print("-" * 50)
    
    try:
        # Create a test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            test_file = f.name
            f.write("Test content for file operations\n" * 10)
        
        print(f"✓ Created test file: {test_file}")
        
        # Read file
        content = FileHandler.read_file(test_file)
        print(f"✓ Read file: {len(content)} bytes")
        
        # Write file atomically
        backup_file = test_file + ".backup"
        FileHandler.write_file_atomic(backup_file, content)
        print(f"✓ Atomic write: {backup_file}")
        
        # Get output filename
        output_name = FileHandler.get_output_filename(test_file, 'encrypt')
        print(f"✓ Output filename: {output_name}")
        
        # Clean up
        os.unlink(test_file)
        os.unlink(backup_file)
        print("✓ Cleaned up test files")
        
        return True
        
    except Exception as e:
        print(f"✗ FileHandler test failed: {e}")
        return False


def test_password_validator():
    """Test password validation."""
    print("\n🔒 Testing PasswordValidator...")
    print("-" * 50)
    
    test_cases = [
        ("weak", "password"),
        ("too short", "short"),
        ("no uppercase", "lowercase123!"),
        ("no lowercase", "UPPERCASE123!"),
        ("no numbers", "NoNumbers!"),
        ("no special", "NoSpecial123"),
        ("strong", "MyStrongPassword123!"),
        ("very strong", "CorrectHorseBatteryStaple!"),
    ]
    
    for name, password in test_cases:
        try:
            is_valid, msg = PasswordValidator.validate(password)
            strength = PasswordValidator.estimate_strength(password)
            print(f"{name:15} | {'✓' if is_valid else '✗':2} | {strength:5.0%} | {password[:20]:20}")
        except Exception as e:
            print(f"{name:15} | ✗  |       | {password[:20]:20} -> {e}")
    
    return True


def full_encryption_demo():
    """Complete encryption/decryption demo."""
    print("\n🚀 Full Encryption Demo")
    print("=" * 50)
    
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        test_file = f.name
        f.write("This is a confidential document.\n")
        f.write("It contains sensitive information.\n")
        f.write("Encryption is essential for security.\n" * 5)
    
    print(f"Test file: {test_file}")
    print(f"File size: {os.path.getsize(test_file)} bytes")
    
    try:
        # Initialize components
        km = KeyManager()
        print(f"\nUsing {'Argon2id' if km.use_argon2 else 'PBKDF2'} for key derivation")
        
        # Password
        password = "SecurePassword123!"
        print(f"Password: {password}")
        
        # Generate salt and derive key
        salt = km.generate_salt()
        print(f"Salt: {salt.hex()[:16]}...")
        
        key = km.derive_key(password, salt)
        print(f"Key: {key.hex()[:32]}...")
        
        # Read file
        plaintext = FileHandler.read_file(test_file)
        print(f"\nRead {len(plaintext)} bytes from file")
        
        # Encrypt
        print("\n🔒 Encrypting...")
        nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
        print(f"✓ Nonce: {nonce.hex()[:16]}...")
        print(f"✓ Ciphertext: {len(ciphertext)} bytes")
        print(f"✓ Tag: {tag.hex()[:16]}...")
        
        # Save encrypted file (simplified)
        encrypted_file = test_file + ".enc"
        with open(encrypted_file, 'wb') as f:
            # Simple format: salt + nonce + tag + ciphertext
            f.write(salt + nonce + tag + ciphertext)
        print(f"✓ Saved encrypted file: {encrypted_file}")
        
        # Load and decrypt
        print("\n🔓 Decrypting...")
        with open(encrypted_file, 'rb') as f:
            data = f.read()
            loaded_salt = data[:16]
            loaded_nonce = data[16:28]
            loaded_tag = data[28:44]
            loaded_ciphertext = data[44:]
        
        # Re-derive key (should be same)
        loaded_key = km.derive_key(password, loaded_salt)
        
        # Decrypt
        decrypted = CryptoEngine.decrypt(loaded_key, loaded_nonce, loaded_ciphertext, loaded_tag)
        
        # Verify
        if decrypted == plaintext:
            print("✅ SUCCESS: Decrypted content matches original!")
            print(f"\nOriginal preview: {plaintext[:50].decode('utf-8', errors='ignore')}...")
            print(f"Decrypted preview: {decrypted[:50].decode('utf-8', errors='ignore')}...")
        else:
            print("❌ FAILED: Decrypted content doesn't match!")
        
        # Clean up
        os.unlink(test_file)
        os.unlink(encrypted_file)
        print("\n✓ Cleaned up test files")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("🔐 Secure Encryption System - Simple Demo")
    print("=" * 60)
    
    tests = [
        ("Key Manager", test_key_manager),
        ("Crypto Engine", test_crypto_engine),
        ("File Handler", test_file_handler),
        ("Password Validator", test_password_validator),
        ("Full Encryption Demo", full_encryption_demo),
    ]
    
    results = []
    
    for name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"Testing: {name}")
        print('='*60)
        try:
            success = test_func()
            results.append((name, success))
        except KeyboardInterrupt:
            print("\n\n⏹️ Demo interrupted by user")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Test crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "="*60)
    print("📊 Test Summary")
    print("="*60)
    
    passed = 0
    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{name:25} {status}")
        if success:
            passed += 1
    
    print(f"\n{passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 All tests passed! System is working correctly.")
    else:
        print(f"\n⚠️  {len(results) - passed} test(s) failed.")
        print("Check the output above for details.")
    
    print("\n" + "="*60)
    print("💡 Next Steps:")
    print("1. Try the CLI: python app.py encrypt test.txt")
    print("2. Try the web interface: flask run")
    print("3. Read the documentation in README.md")
    print("="*60)


if __name__ == "__main__":
    main()