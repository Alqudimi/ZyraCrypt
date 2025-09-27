# Troubleshooting Guide

This guide helps you diagnose and resolve common issues when using the Advanced Encryption System.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Import and Module Errors](#import-and-module-errors)
3. [Cryptographic Errors](#cryptographic-errors)
4. [Performance Issues](#performance-issues)
5. [API and Integration Problems](#api-and-integration-problems)
6. [Platform-Specific Issues](#platform-specific-issues)
7. [Debugging Tools](#debugging-tools)
8. [Getting Help](#getting-help)

## Installation Issues

### Problem: Package Installation Fails

**Symptoms:**
```
ERROR: Failed building wheel for <package>
ModuleNotFoundError: No module named 'Cython'
```

**Solutions:**

1. **Install Cython first:**
   ```bash
   pip install Cython
   pip install -r requirements.txt
   ```

2. **Use pre-compiled packages:**
   ```bash
   pip install --only-binary=all -r requirements.txt
   ```

3. **Install system dependencies (Linux):**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install python3-dev build-essential libffi-dev

   # CentOS/RHEL
   sudo yum install python3-devel gcc openssl-devel libffi-devel
   ```

4. **Install system dependencies (macOS):**
   ```bash
   # Install Xcode command line tools
   xcode-select --install
   
   # Install Homebrew if needed
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   
   # Install dependencies
   brew install openssl libffi
   ```

### Problem: Python Version Compatibility

**Symptoms:**
```
ERROR: Package requires Python >=3.11 but you have Python 3.9
```

**Solutions:**

1. **Install Python 3.11+:**
   ```bash
   # Using pyenv
   pyenv install 3.11.5
   pyenv global 3.11.5
   
   # Using conda
   conda create -n encryption python=3.11
   conda activate encryption
   ```

2. **Check Python version:**
   ```bash
   python --version
   python3 --version
   ```

### Problem: Dependency Conflicts

**Symptoms:**
```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed
```

**Solutions:**

1. **Use fresh virtual environment:**
   ```bash
   python -m venv fresh_env
   source fresh_env/bin/activate  # Linux/macOS
   # fresh_env\Scripts\activate  # Windows
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

2. **Resolve conflicts manually:**
   ```bash
   pip install --upgrade pip setuptools wheel
   pip install --no-deps -r requirements.txt
   pip check  # Verify dependencies
   ```

## Import and Module Errors

### Problem: Cannot Import Encryption Modules

**Symptoms:**
```python
ModuleNotFoundError: No module named 'core_cryptography'
ImportError: cannot import name 'SymmetricEncryption'
```

**Diagnosis:**
```python
import sys
import os

# Check if paths are correctly set
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')

print("Encryption root exists:", os.path.exists(encryption_root))
print("Encryption src exists:", os.path.exists(encryption_src))
print("Python path:", sys.path[:3])
```

**Solutions:**

1. **Correct path setup:**
   ```python
   import sys
   import os

   # Add the encryption system to Python path
   encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
   encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
   sys.path.insert(0, encryption_root)
   sys.path.insert(0, encryption_src)

   # Now import modules
   from core_cryptography.symmetric_encryption import SymmetricEncryption
   ```

2. **Install as package:**
   ```bash
   cd alqudimi_encryption_system
   pip install -e .
   ```

### Problem: Cython Extension Loading Errors

**Symptoms:**
```
ImportError: dynamic module does not define module export function
ImportError: cannot import name 'SymmetricEncryption' from 'core_cryptography.symmetric_encryption'
```

**Solutions:**

1. **Rebuild extensions:**
   ```bash
   cd alqudimi_encryption_system
   python setup.py clean --all
   python setup.py build_ext --inplace
   ```

2. **Use Python fallback:**
   ```python
   # Check if compiled version is available
   try:
       from core_cryptography.symmetric_encryption import SymmetricEncryption
   except ImportError:
       # Fall back to Python implementation
       import sys
       sys.path.append('path/to/python/sources')
       from symmetric_encryption import SymmetricEncryption
   ```

## Cryptographic Errors

### Problem: Invalid Key or IV Length

**Symptoms:**
```python
ValueError: Invalid key length: expected 32 bytes, got 16
ValueError: Invalid IV length for AES-GCM: expected 12 bytes, got 16
```

**Solutions:**

1. **Generate correct key sizes:**
   ```python
   import os
   
   # AES-256 key (32 bytes)
   aes_key = os.urandom(32)
   
   # AES-GCM IV (12 bytes recommended)
   aes_iv = os.urandom(12)
   
   # ChaCha20 key (32 bytes)
   chacha_key = os.urandom(32)
   
   # ChaCha20 nonce (12 bytes)
   chacha_nonce = os.urandom(12)
   ```

2. **Validate inputs:**
   ```python
   def validate_aes_inputs(key: bytes, iv: bytes):
       if len(key) not in [16, 24, 32]:
           raise ValueError(f"Invalid key length: {len(key)} bytes")
       if len(iv) != 12:
           raise ValueError(f"Invalid IV length: {len(iv)} bytes")
   ```

### Problem: Authentication Tag Verification Failed

**Symptoms:**
```python
cryptography.exceptions.InvalidTag: Authentication tag verification failed
```

**Diagnosis:**
```python
# Check if ciphertext or tag was corrupted
original_ciphertext = b"..."
original_tag = b"..."

# Verify lengths
print(f"Ciphertext length: {len(original_ciphertext)}")
print(f"Tag length: {len(original_tag)}")

# Check for corruption
if len(original_tag) != 16:
    print("ERROR: Tag length incorrect for AES-GCM")
```

**Solutions:**

1. **Verify data integrity:**
   ```python
   # Store tag separately from ciphertext
   ciphertext, tag = symmetric.encrypt_aes_gcm(key, iv, plaintext)
   
   # Don't concatenate - keep separate
   # WRONG: combined = ciphertext + tag
   # RIGHT: store separately
   
   # Decrypt with separate components
   decrypted = symmetric.decrypt_aes_gcm(key, iv, ciphertext, tag)
   ```

2. **Check for encoding issues:**
   ```python
   import base64
   
   # When storing/transmitting, use proper encoding
   ciphertext_b64 = base64.b64encode(ciphertext).decode()
   tag_b64 = base64.b64encode(tag).decode()
   
   # When retrieving, decode properly
   ciphertext = base64.b64decode(ciphertext_b64.encode())
   tag = base64.b64decode(tag_b64.encode())
   ```

### Problem: Key Derivation Errors

**Symptoms:**
```python
ValueError: Invalid salt length
TypeError: Password must be bytes
```

**Solutions:**

1. **Proper KDF usage:**
   ```python
   from key_management.enhanced_kdf_password import EnhancedKDF, KDFAlgorithm
   
   kdf = EnhancedKDF()
   password = "user_password".encode('utf-8')  # Convert to bytes
   salt = os.urandom(32)  # 32-byte salt
   
   result = kdf.derive_key(
       password=password,
       salt=salt,
       algorithm=KDFAlgorithm.ARGON2ID,
       key_length=32
   )
   ```

2. **Input validation:**
   ```python
   def validate_kdf_inputs(password: bytes, salt: bytes):
       if not isinstance(password, bytes):
           raise TypeError("Password must be bytes")
       if len(salt) < 16:
           raise ValueError("Salt must be at least 16 bytes")
       if len(password) == 0:
           raise ValueError("Password cannot be empty")
   ```

## Performance Issues

### Problem: Slow Encryption Operations

**Symptoms:**
- Encryption takes much longer than expected
- High CPU usage during crypto operations
- Memory usage grows unexpectedly

**Diagnosis:**
```python
import time
import os
from core_cryptography.encryption_framework import EncryptionFramework

def benchmark_encryption():
    framework = EncryptionFramework()
    key = os.urandom(32)
    data = os.urandom(1024)  # 1KB test data
    
    # Measure single operation
    start = time.time()
    algorithm, iv, ciphertext, tag = framework.encrypt(data, key)
    duration = time.time() - start
    
    print(f"Encryption time: {duration*1000:.2f} ms")
    print(f"Throughput: {len(data)/duration/1024:.2f} KB/s")
    
    return duration

benchmark_encryption()
```

**Solutions:**

1. **Use hardware acceleration:**
   ```python
   # Check if AES-NI is available
   import platform
   import subprocess
   
   if platform.system() == "Linux":
       try:
           result = subprocess.run(['grep', 'aes', '/proc/cpuinfo'], 
                                 capture_output=True, text=True)
           if result.returncode == 0:
               print("AES-NI hardware acceleration available")
       except:
           pass
   ```

2. **Optimize for bulk operations:**
   ```python
   # Instead of encrypting many small pieces
   for small_data in data_pieces:
       encrypt(small_data)  # Inefficient
   
   # Combine data first
   combined_data = b''.join(data_pieces)
   encrypted = encrypt(combined_data)  # More efficient
   ```

3. **Use appropriate algorithms:**
   ```python
   # For small data (< 1KB), prefer AES-GCM
   # For large data (> 1MB), consider ChaCha20-Poly1305
   
   def choose_algorithm(data_size):
       if data_size < 1024:
           return "AES-GCM"
       else:
           return "ChaCha20-Poly1305"
   ```

### Problem: High Memory Usage

**Symptoms:**
- Memory usage grows during encryption
- Out of memory errors with large files
- Memory not released after operations

**Solutions:**

1. **Use streaming for large data:**
   ```python
   def encrypt_large_file(file_path, key, chunk_size=8192):
       with open(file_path, 'rb') as infile:
           while True:
               chunk = infile.read(chunk_size)
               if not chunk:
                   break
               
               # Process chunk
               encrypted_chunk = encrypt(chunk, key)
               yield encrypted_chunk
               
               # Explicitly delete to help GC
               del chunk, encrypted_chunk
   ```

2. **Clear sensitive data:**
   ```python
   def secure_encrypt(data, key):
       try:
           result = encrypt(data, key)
           return result
       finally:
           # Clear sensitive data
           if isinstance(data, bytearray):
               for i in range(len(data)):
                   data[i] = 0
   ```

## API and Integration Problems

### Problem: Flask API Not Starting

**Symptoms:**
```
ValueError: SESSION_SECRET environment variable is required
ModuleNotFoundError: No module named 'flask'
```

**Solutions:**

1. **Set environment variables:**
   ```bash
   export SESSION_SECRET="your-secure-secret-key"
   export CORS_ORIGINS="http://localhost:*"
   ```

2. **Install web dependencies:**
   ```bash
   pip install flask flask-cors
   ```

3. **Check app configuration:**
   ```python
   import os
   from flask import Flask

   app = Flask(__name__)
   
   # Verify environment
   if not os.environ.get("SESSION_SECRET"):
       print("WARNING: SESSION_SECRET not set")
       os.environ["SESSION_SECRET"] = "development-key-only"
   
   app.secret_key = os.environ.get("SESSION_SECRET")
   ```

### Problem: CORS Issues in Web Browser

**Symptoms:**
```
Access to fetch at 'http://localhost:5000/api/encrypt' from origin 'http://localhost:3000' has been blocked by CORS policy
```

**Solutions:**

1. **Configure CORS properly:**
   ```python
   from flask_cors import CORS
   
   # Allow specific origins
   CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"])
   
   # Or configure via environment
   cors_origins = os.environ.get('CORS_ORIGINS', 'http://localhost:*').split(',')
   CORS(app, origins=cors_origins)
   ```

2. **Set environment variable:**
   ```bash
   export CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:3000,https://mydomain.com"
   ```

### Problem: API Authentication Errors

**Symptoms:**
```json
{"error": "Invalid API key"}
{"error": "Authentication required"}
```

**Solutions:**

1. **Implement proper API authentication:**
   ```python
   from functools import wraps
   import hmac
   import hashlib
   
   def require_api_key(f):
       @wraps(f)
       def decorated_function(*args, **kwargs):
           api_key = request.headers.get('X-API-Key')
           if not api_key or not validate_api_key(api_key):
               return jsonify({'error': 'Invalid API key'}), 401
           return f(*args, **kwargs)
       return decorated_function
   
   def validate_api_key(provided_key):
       expected_key = os.environ.get('API_KEY')
       if not expected_key:
           return False
       return hmac.compare_digest(provided_key, expected_key)
   ```

## Platform-Specific Issues

### Windows Issues

**Problem: Build Tools Missing**
```
Microsoft Visual C++ 14.0 is required
```

**Solutions:**
1. Install Visual Studio Build Tools
2. Use pre-compiled packages: `pip install --only-binary=all`

**Problem: Path Length Limitations**
```
OSError: [Errno 36] File name too long
```

**Solutions:**
1. Enable long path support in Windows 10+
2. Use shorter directory names
3. Work from root directory (C:\project)

### macOS Issues

**Problem: OpenSSL Linking**
```
fatal error: 'openssl/opensslv.h' file not found
```

**Solutions:**
```bash
brew install openssl
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
pip install cryptography
```

### Linux Issues

**Problem: Missing System Libraries**
```
fatal error: Python.h: No such file or directory
```

**Solutions:**
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libssl-dev libffi-dev

# CentOS/RHEL
sudo yum install python3-devel openssl-devel libffi-devel

# Alpine Linux
apk add python3-dev openssl-dev libffi-dev gcc musl-dev
```

## Debugging Tools

### Enable Debug Logging

```python
import logging

# Configure logging for debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Enable crypto library debug logging
logger = logging.getLogger('alqudimi_encryption_system')
logger.setLevel(logging.DEBUG)
```

### Environment Information Script

```python
#!/usr/bin/env python3
"""Environment information for debugging."""

import sys
import os
import platform
import subprocess

def check_environment():
    """Check system environment for debugging."""
    print("=== Environment Information ===")
    print(f"Python version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Architecture: {platform.architecture()}")
    print(f"Python executable: {sys.executable}")
    
    print("\n=== Python Path ===")
    for i, path in enumerate(sys.path[:5]):
        print(f"{i}: {path}")
    
    print("\n=== Environment Variables ===")
    crypto_vars = [k for k in os.environ.keys() if 'CRYPTO' in k.upper() or 'SECRET' in k.upper()]
    for var in crypto_vars:
        value = os.environ[var]
        masked = value[:4] + "*" * (len(value) - 4) if len(value) > 4 else "***"
        print(f"{var}: {masked}")
    
    print("\n=== Package Versions ===")
    packages = ['cryptography', 'flask', 'cython', 'liboqs-python']
    for package in packages:
        try:
            import importlib
            module = importlib.import_module(package.replace('-', '_'))
            version = getattr(module, '__version__', 'unknown')
            print(f"{package}: {version}")
        except ImportError:
            print(f"{package}: not installed")
    
    print("\n=== Library Import Test ===")
    try:
        # Test basic import
        encryption_root = os.path.join(os.getcwd(), 'alqudimi_encryption_system')
        encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
        sys.path.insert(0, encryption_root)
        sys.path.insert(0, encryption_src)
        
        from core_cryptography.symmetric_encryption import SymmetricEncryption
        print("✓ Core encryption import successful")
        
        # Test initialization
        symmetric = SymmetricEncryption()
        print("✓ Symmetric encryption initialization successful")
        
    except Exception as e:
        print(f"✗ Import failed: {e}")

if __name__ == "__main__":
    check_environment()
```

### Performance Profiling

```python
import cProfile
import pstats
from core_cryptography.encryption_framework import EncryptionFramework

def profile_encryption():
    """Profile encryption performance."""
    framework = EncryptionFramework()
    key = os.urandom(32)
    data = os.urandom(10240)  # 10KB
    
    def test_function():
        for _ in range(100):
            framework.encrypt(data, key)
    
    # Profile the function
    profiler = cProfile.Profile()
    profiler.enable()
    test_function()
    profiler.disable()
    
    # Print results
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(10)

profile_encryption()
```

## Getting Help

### Self-Diagnosis Checklist

Before seeking help, run through this checklist:

- [ ] Python version is 3.11 or higher
- [ ] All dependencies are installed correctly
- [ ] Environment variables are set properly
- [ ] Import paths are configured correctly
- [ ] No conflicting package versions
- [ ] System has required build tools (if compiling)
- [ ] Sufficient disk space and memory
- [ ] Firewall/antivirus not blocking operations

### Gathering Information for Support

When reporting issues, include:

1. **Environment information** (run script above)
2. **Complete error message** with stack trace
3. **Minimal reproducible example**
4. **Expected vs actual behavior**
5. **System specifications**
6. **Library version** and installation method

### Support Channels

1. **GitHub Issues**: For bug reports and feature requests
2. **GitHub Discussions**: For questions and community help
3. **Documentation**: Check [User Guide](user_guide.md) and [API Reference](api.md)
4. **Security Issues**: Contact security@alqudimi.com (confidential)

### Creating Minimal Reproducible Examples

```python
#!/usr/bin/env python3
"""Minimal example demonstrating the issue."""

import sys
import os

# Setup (include this in all bug reports)
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
sys.path.insert(0, encryption_root)
sys.path.insert(0, encryption_src)

def demonstrate_issue():
    """Minimal code that reproduces the issue."""
    try:
        # Your problematic code here
        from core_cryptography.symmetric_encryption import SymmetricEncryption
        symmetric = SymmetricEncryption()
        
        # ... rest of your code
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("Python version:", sys.version)
    print("Platform:", sys.platform)
    demonstrate_issue()
```

---

Remember: When in doubt, check the [complete documentation](user_guide.md) and don't hesitate to ask for help through the appropriate channels!