#!/usr/bin/env python3
"""
Quick test to verify installation.
"""

import sys

print("🔧 Checking installation...")

# Check Python version
print(f"Python version: {sys.version}")

# Check imports
print("\n📦 Testing imports:")
modules = [
    ('cryptography', 'cryptography'),
    ('argon2', 'argon2'),
    ('flask', 'flask'),
    ('click', 'click'),
]

for module_name, import_name in modules:
    try:
        __import__(import_name)
        print(f"  ✅ {module_name}")
    except ImportError as e:
        print(f"  ❌ {module_name}: {e}")

# Check our modules
print("\n🔐 Testing local modules:")
local_modules = [
    ('core.crypto_engine', 'CryptoEngine'),
    ('core.key_manager', 'KeyManager'),
    ('security.constants', 'AES_KEY_SIZE'),
]

try:
    sys.path.insert(0, '.')
    for module, attr in local_modules:
        try:
            mod = __import__(module, fromlist=[attr])
            print(f"  ✅ {module}")
        except Exception as e:
            print(f"  ❌ {module}: {e}")
except Exception as e:
    print(f"  ❌ Failed to import local modules: {e}")

print("\n✅ Installation check complete!")
print("\nTo run a full demo: python examples/simple_demo.py")
print("To use CLI: python app.py --help")