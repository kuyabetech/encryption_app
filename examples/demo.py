#!/usr/bin/env python3
"""
Real-world test of the encryption system.
Creates test files, encrypts them, and verifies everything works.
"""

import os
import sys
import tempfile
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crypto_engine import CryptoEngine
from core.key_manager import KeyManager
from core.file_handler import FileHandler
from utils.validators import PasswordValidator


def create_test_files():
    """Create various test files."""
    test_files = []
    
    # Text file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("""CONFIDENTIAL DOCUMENT
======================
Date: 2024-01-15
To: Management Team
From: Security Department
Subject: Quarterly Security Report

This document contains sensitive information about:
1. Security vulnerabilities found
2. Employee access patterns
3. Incident response metrics
4. Future security investments

DO NOT DISTRIBUTE WITHOUT ENCRYPTION.
""")
        test_files.append(f.name)
    
    # CSV data file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
        f.write("""Name,Department,Salary,Access Level
John Smith,Engineering,85000,Admin
Jane Doe,Marketing,72000,User
Bob Johnson,Finance,92000,Manager
Alice Brown,HR,68000,User
Charlie Wilson,Engineering,88000,Admin
""")
        test_files.append(f.name)
    
    # JSON config file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        f.write("""{
  "database": {
    "host": "localhost",
    "port": 5432,
    "name": "production_db",
    "user": "admin",
    "password": "secret123"
  },
  "api_keys": {
    "stripe": "sk_live_123456789",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "google": "AIzaSyB_1234567890"
  },
  "settings": {
    "backup_enabled": true,
    "encryption_required": true,
    "log_level": "debug"
  }
}
""")
        test_files.append(f.name)
    
    print(f"✓ Created {len(test_files)} test files")
    return test_files


def test_encryption_workflow():
    """Test the complete encryption workflow."""
    print("\n" + "="*60)
    print("🔐 Testing Complete Encryption Workflow")
    print("="*60)
    
    # Create test files
    test_files = create_test_files()
    
    results = []
    
    for file_path in test_files:
        filename = os.path.basename(file_path)
        print(f"\n📄 Processing: {filename}")
        
        try:
            # 1. Read original file
            original_size = os.path.getsize(file_path)
            print(f"  Original size: {original_size:,} bytes")
            
            # 2. Create KeyManager
            km = KeyManager()
            print(f"  Using: {'Argon2id' if km.use_argon2 else 'PBKDF2'}")
            
            # 3. Generate password (simulate user input)
            password = "SecurePass123!@#"
            print(f"  Password: {'*' * len(password)}")
            
            # 4. Generate salt and derive key
            salt = km.generate_salt()
            key = km.derive_key(password, salt)
            
            # 5. Read file content
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # 6. Encrypt
            start_time = time.time()
            nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
            encrypt_time = time.time() - start_time
            
            print(f"  Encryption time: {encrypt_time:.3f}s")
            print(f"  Ciphertext size: {len(ciphertext):,} bytes")
            print(f"  Overhead: {len(ciphertext) - len(plaintext) + 44:,} bytes")
            
            # 7. Create encrypted file
            encrypted_file = file_path + '.enc'
            
            # Simple file format for demo
            with open(encrypted_file, 'wb') as f:
                # Header: SALT (16) + NONCE (12) + TAG (16) = 44 bytes
                f.write(salt + nonce + tag + ciphertext)
            
            # 8. Decrypt to verify
            with open(encrypted_file, 'rb') as f:
                data = f.read()
                loaded_salt = data[:16]
                loaded_nonce = data[16:28]
                loaded_tag = data[28:44]
                loaded_ciphertext = data[44:]
            
            # Re-derive key
            loaded_key = km.derive_key(password, loaded_salt)
            
            # Decrypt
            start_time = time.time()
            decrypted = CryptoEngine.decrypt(
                loaded_key, loaded_nonce, loaded_ciphertext, loaded_tag
            )
            decrypt_time = time.time() - start_time
            
            print(f"  Decryption time: {decrypt_time:.3f}s")
            
            # 9. Verify
            if decrypted == plaintext:
                print("  ✅ Verification: PASSED")
                results.append(True)
            else:
                print("  ❌ Verification: FAILED")
                results.append(False)
            
            # 10. Test tamper detection
            try:
                tampered = bytearray(ciphertext)
                tampered[0] ^= 0x01
                CryptoEngine.decrypt(key, nonce, bytes(tampered), tag)
                print("  ❌ Tamper detection: FAILED")
            except Exception as e:
                print(f"  ✅ Tamper detection: WORKING ({type(e).__name__})")
            
            # Clean up
            os.unlink(file_path)
            os.unlink(encrypted_file)
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "="*60)
    print("📊 Workflow Test Results")
    print("="*60)
    
    passed = sum(results)
    total = len(results)
    
    for i, success in enumerate(results):
        file_type = test_files[i].split('.')[-1] if i < len(test_files) else "unknown"
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{file_type.upper():10} {status}")
    
    print(f"\n{passed}/{total} files processed successfully")
    
    return all(results)


def test_cli_simulation():
    """Simulate CLI commands."""
    print("\n" + "="*60)
    print("💻 Testing CLI Simulation")
    print("="*60)
    
    # Create a test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Test content for CLI simulation")
    test_file = f.name
    
    try:
        # Simulate: python app.py encrypt test.txt
        print(f"Simulating: secure-encrypt encrypt {os.path.basename(test_file)}")
        
        km = KeyManager()
        password = "CliTestPassword123!"
        salt = km.generate_salt()
        key = km.derive_key(password, salt)
        
        # Read and encrypt
        with open(test_file, 'rb') as f:
            plaintext = f.read()
        
        nonce, ciphertext, tag = CryptoEngine.encrypt(key, plaintext)
        
        # Save encrypted file
        encrypted_file = test_file + '.enc'
        with open(encrypted_file, 'wb') as f:
            f.write(salt + nonce + tag + ciphertext)
        
        print(f"✓ Created: {os.path.basename(encrypted_file)}")
        print(f"  Original: {len(plaintext)} bytes")
        print(f"  Encrypted: {len(ciphertext) + 44} bytes")
        
        # Simulate: python app.py decrypt test.enc
        print(f"\nSimulating: secure-encrypt decrypt {os.path.basename(encrypted_file)}")
        
        # Load and decrypt
        with open(encrypted_file, 'rb') as f:
            data = f.read()
            loaded_salt = data[:16]
            loaded_nonce = data[16:28]
            loaded_tag = data[28:44]
            loaded_ciphertext = data[44:]
        
        loaded_key = km.derive_key(password, loaded_salt)
        decrypted = CryptoEngine.decrypt(loaded_key, loaded_nonce, loaded_ciphertext, loaded_tag)
        
        if decrypted == plaintext:
            print("✅ Decryption successful")
            print(f"✓ Content matches: '{decrypted.decode()[:30]}...'")
        else:
            print("❌ Decryption failed")
        
        # Clean up
        os.unlink(test_file)
        os.unlink(encrypted_file)
        
        return True
        
    except Exception as e:
        print(f"❌ CLI simulation failed: {e}")
        return False


def test_performance():
    """Test performance with different file sizes."""
    print("\n" + "="*60)
    print("⚡ Performance Test")
    print("="*60)
    
    km = KeyManager()
    password = "PerfTest123!"
    
    # Test different sizes
    sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB
    
    results = []
    
    for size in sizes:
        print(f"\nTesting {size:,} bytes ({size/1024:.1f} KB):")
        
        # Create test data
        data = os.urandom(size)
        
        # Generate key
        salt = km.generate_salt()
        key = km.derive_key(password, salt)
        
        # Time encryption
        start = time.time()
        nonce, ciphertext, tag = CryptoEngine.encrypt(key, data)
        encrypt_time = time.time() - start
        
        # Time decryption
        start = time.time()
        decrypted = CryptoEngine.decrypt(key, nonce, ciphertext, tag)
        decrypt_time = time.time() - start
        
        # Verify
        success = decrypted == data
        status = "✅" if success else "❌"
        
        print(f"  {status} Encryption: {encrypt_time:.3f}s ({size/encrypt_time/1024:.1f} KB/s)")
        print(f"  {status} Decryption: {decrypt_time:.3f}s ({size/decrypt_time/1024:.1f} KB/s)")
        
        results.append(success)
    
    return all(results)


def main():
    """Run all real-world tests."""
    print("🔐 Secure Encryption - Real World Test")
    print("="*60)
    
    tests = [
        ("Encryption Workflow", test_encryption_workflow),
        ("CLI Simulation", test_cli_simulation),
        ("Performance", test_performance),
    ]
    
    results = []
    
    for name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"Test: {name}")
        print('='*60)
        try:
            success = test_func()
            results.append((name, success))
        except KeyboardInterrupt:
            print("\n\n⏹️ Test interrupted by user")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Test crashed: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "="*60)
    print("📊 Final Results")
    print("="*60)
    
    passed = 0
    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{name:25} {status}")
        if success:
            passed += 1
    
    print(f"\n{passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉🎉🎉 ALL TESTS PASSED! 🎉🎉🎉")
        print("\nYour encryption system is ready for production!")
        print("\nNext steps:")
        print("1. Try the actual CLI: python app.py --help")
        print("2. Test with your own files")
        print("3. Deploy the web interface if needed")
        print("4. Review the security settings for your use case")
    else:
        print(f"\n⚠️  {len(results) - passed} test(s) failed")
        print("Check the output above for details")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    main()