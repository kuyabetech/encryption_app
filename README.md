# 🔐 Secure File Encryption

A production-ready, secure file encryption tool using AES-256-GCM and Argon2 key derivation.

## Features

- **Military-grade encryption**: AES-256-GCM authenticated encryption
- **Secure key derivation**: Argon2id (memory-hard) or PBKDF2 fallback
- **Tamper detection**: GCM authentication tags prevent file modification
- **Atomic operations**: Prevents file corruption on write failures
- **Password strength validation**: Enforces strong passwords
- **Cross-platform**: Works on Windows, macOS, and Linux
- **No external dependencies**: All crypto from vetted libraries

## Installation

```bash
# Install from source
git clone https://github.com/yourusername/secure-encrypt.git
cd secure-encrypt
pip install -e .

# Or install directly
pip install git+https://github.com/yourusername/secure-encrypt.git


# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the demo
python examples/demo.py

# 3. Test encryption
echo "Hello, secret world!" > test.txt
python app.py encrypt test.txt
# Enter password when prompted

# 4. Test decryption
python app.py decrypt test.enc
# Enter same password

# 5. Compare files
diff test.txt test.decrypted
# Should show no differences

# 6. Clean up
rm test.txt test.enc test.decrypted