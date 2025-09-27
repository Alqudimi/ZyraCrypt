# 🔧 ZyraCrypt Troubleshooting Guide

This guide helps you diagnose and resolve common issues with ZyraCrypt.

## 📋 Table of Contents

- [Installation Issues](#installation-issues)
- [Import Errors](#import-errors)
- [Cryptographic Errors](#cryptographic-errors)
- [Performance Issues](#performance-issues)
- [API Server Issues](#api-server-issues)
- [Testing Issues](#testing-issues)
- [Environment Issues](#environment-issues)
- [Common Error Messages](#common-error-messages)
- [Debugging Tips](#debugging-tips)
- [Getting Help](#getting-help)

## 🚨 Installation Issues

### Problem: `pip install zyracrypt` fails

#### Error: "Could not find a version that satisfies the requirement zyracrypt"
**Solution**:
```bash
# Update pip first
pip install --upgrade pip

# Install with verbose output for debugging
pip install -v zyracrypt

# Try with specific index
pip install --index-url https://pypi.org/simple/ zyracrypt
```

#### Error: "Microsoft Visual C++ 14.0 is required" (Windows)
**Solution**:
1. Install **Microsoft C++ Build Tools**
2. Or install **Visual Studio** with C++ support
3. Alternative: Use pre-compiled wheels from PyPI

#### Error: "Failed building wheel for cryptography"
**Solution**:
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install build-essential libffi-dev python3-dev

# Install system dependencies (CentOS/RHEL)
sudo yum install gcc openssl-devel libffi-devel python3-devel

# macOS: Install Xcode command line tools
xcode-select --install
```

### Problem: Dependencies conflict with existing packages

**Solution**:
```bash
# Use virtual environment (recommended)
python -m venv zyracrypt-env
source zyracrypt-env/bin/activate  # Linux/macOS
# zyracrypt-env\Scripts\activate  # Windows

pip install zyracrypt

# Or install with dependency resolver
pip install --upgrade-strategy eager zyracrypt
```

## 🔍 Import Errors

### Problem: `ModuleNotFoundError: No module named 'zyracrypt'`

#### After installation via pip
**Diagnosis**:
```bash
# Check if package is installed
pip list | grep zyracrypt

# Check Python path
python -c "import sys; print(sys.path)"
```

**Solution**:
```bash
# Reinstall package
pip uninstall zyracrypt
pip install zyracrypt

# Or install in user directory
pip install --user zyracrypt
```

#### Development installation
**Solution**:
```bash
# Install in editable mode
cd /path/to/ZyraCrypt
pip install -e .

# Verify installation
python -c "import zyracrypt; print('Success!')"
```

### Problem: Import path errors with old code (v1.x)

#### Error: "No module named 'alqudimi_encryption_system'"
**Migration needed**:
```python
# Old import (v1.x) - REMOVE
from alqudimi_encryption_system.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption

# New import (v2.0+) - USE THIS
from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption
```

### Problem: Specific module import failures

#### Error: "No module named 'nacl'" or similar dependency errors
**Solution**:
```bash
# Install missing dependencies manually
pip install pynacl cryptography argon2-cffi

# Or reinstall with dependencies
pip install --force-reinstall zyracrypt
```

## 🔐 Cryptographic Errors

### Problem: "Invalid key length" errors

#### AES key length errors
**Common causes**:
- Key not 16, 24, or 32 bytes for AES-128/192/256
- Using string instead of bytes

**Solution**:
```python
import os

# Correct: Generate proper key length
key = os.urandom(32)  # 256-bit key for AES-256

# Incorrect examples to avoid:
# key = "password"           # String, not bytes
# key = b"short"             # Too short
# key = os.urandom(20)       # Invalid length
```

#### RSA key size errors
**Solution**:
```python
from zyracrypt.encryption_system.src.core_cryptography.asymmetric_encryption import AsymmetricEncryption

asym_enc = AsymmetricEncryption()

# Use standard key sizes: 2048, 3072, or 4096
private_key, public_key = asym_enc.generate_rsa_key_pair(2048)
```

### Problem: "Invalid signature" or verification failures

#### Debug signature verification
**Solution**:
```python
# Ensure data hasn't been modified
original_data = b"exact message that was signed"
signature = sign_function(private_key, original_data)

# Verify with exact same data
is_valid = verify_function(public_key, original_data, signature)
```

### Problem: EnhancedKDF parameter errors

#### Error: "KeyError: 32" or similar parameter issues
**Solution**:
```python
from zyracrypt.encryption_system.src.key_management.enhanced_kdf_password import (
    EnhancedKDF, KDFAlgorithm, SecurityProfile
)

kdf = EnhancedKDF()

# Correct usage with SecurityProfile enum
result = kdf.derive_key(
    password=b"password",
    salt=os.urandom(32),
    algorithm=KDFAlgorithm.ARGON2ID,
    security_profile=SecurityProfile.INTERACTIVE,  # Use enum, not integer
    key_length=32
)
```

## ⚡ Performance Issues

### Problem: Slow encryption performance

#### Diagnosis
**Test performance**:
```python
import time
from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption

sym_enc = SymmetricEncryption()
key = os.urandom(32)
data = b"x" * 10000  # 10KB test data

start = time.time()
iv, ciphertext, tag = sym_enc.encrypt_aes_gcm(key, data)
print(f"Encryption time: {time.time() - start:.4f} seconds")
```

#### Solutions
1. **Use appropriate algorithms**:
   ```python
   # Fast for small data
   result = framework.encrypt(small_data, key)  # Auto-selects optimal algorithm
   
   # Batch process large datasets
   results = [sym_enc.encrypt_aes_gcm(key, chunk) for chunk in data_chunks]
   ```

2. **Reuse encryption objects**:
   ```python
   # Good: Create once, reuse
   sym_enc = SymmetricEncryption()
   for data in dataset:
       result = sym_enc.encrypt_aes_gcm(key, data)
   
   # Bad: Create for each operation
   for data in dataset:
       sym_enc = SymmetricEncryption()  # Inefficient
       result = sym_enc.encrypt_aes_gcm(key, data)
   ```

### Problem: High memory usage

**Solutions**:
1. **Process data in chunks**:
   ```python
   def encrypt_large_file(file_path, key, chunk_size=8192):
       results = []
       with open(file_path, 'rb') as f:
           while chunk := f.read(chunk_size):
               result = sym_enc.encrypt_aes_gcm(key, chunk)
               results.append(result)
       return results
   ```

2. **Enable garbage collection**:
   ```python
   import gc
   
   # After processing large datasets
   gc.collect()
   ```

## 🌐 API Server Issues

### Problem: Flask server won't start

#### Error: "Address already in use" (Port 5000)
**Solution**:
```bash
# Find process using port 5000
lsof -i :5000                    # macOS/Linux
netstat -ano | findstr :5000     # Windows

# Kill the process and restart
kill -9 <PID>                    # macOS/Linux

# Or use different port
export PORT=8080
python main.py
```

#### Error: "SESSION_SECRET environment variable not set"
**Solution**:
```bash
# Set required environment variable
export SESSION_SECRET="your-secure-random-secret-key-here"

# Generate secure secret
python -c "import secrets; print(secrets.token_hex(32))"

# Start server
python main.py
```

### Problem: CORS errors in web applications

**Solution**:
```bash
# Set CORS origins for development
export CORS_ORIGINS="http://localhost:*,http://127.0.0.1:*,https://yourdomain.com"

# For production, set specific origins
export CORS_ORIGINS="https://production-domain.com"
```

### Problem: API returns 500 errors

#### Debug with verbose logging
**Solution**:
```python
# Add to app.py for debugging
import logging
logging.basicConfig(level=logging.DEBUG)

# Check server logs for specific error messages
# Look for cryptographic library errors or import issues
```

## 🧪 Testing Issues

### Problem: Tests fail with "EnhancedKDF" errors

#### Error: "KeyError: 32" in test suite
**Solution**: Update test to use correct API:
```python
# Incorrect test code
result = enhanced_kdf.derive_key(password, salt, KDFAlgorithm.ARGON2ID, 32)

# Correct test code
result = enhanced_kdf.derive_key(
    password, 
    salt, 
    KDFAlgorithm.ARGON2ID, 
    SecurityProfile.INTERACTIVE, 
    32
)
```

### Problem: Tests fail due to missing dependencies

**Solution**:
```bash
# Install test dependencies
pip install pytest pytest-cov

# Install all optional dependencies
pip install zyracrypt[dev]

# Run specific test module
python -m pytest tests/test_core_cryptography.py -v
```

### Problem: Performance tests fail due to timeouts

**Solution**:
```bash
# Run tests with increased timeout
python -m pytest tests/ --timeout=300

# Skip slow tests
python -m pytest tests/ -m "not slow"

# Run performance tests separately
python corrected_comprehensive_test.py
```

## 🌍 Environment Issues

### Problem: Different behavior on different operating systems

#### Windows-specific issues
**Common solutions**:
```bash
# Use Python from Microsoft Store or official python.org
# Avoid Anaconda Python for cryptographic libraries

# Install Microsoft C++ Build Tools
# Set environment variables properly in PowerShell/CMD
```

#### macOS-specific issues
**Solution**:
```bash
# Install Xcode command line tools
xcode-select --install

# Use Homebrew Python if system Python causes issues
brew install python@3.11

# Set proper PATH
export PATH="/usr/local/opt/python@3.11/bin:$PATH"
```

#### Linux-specific issues
**Solution**:
```bash
# Install development packages
sudo apt-get install python3-dev libffi-dev libssl-dev  # Ubuntu/Debian
sudo yum install python3-devel libffi-devel openssl-devel  # CentOS/RHEL

# Ensure sufficient entropy for cryptographic operations
cat /proc/sys/kernel/random/entropy_avail  # Should be > 1000
```

## ❗ Common Error Messages

### "ValueError: Invalid key format"
**Cause**: Key is not bytes or wrong length  
**Solution**: Use `os.urandom(32)` for 256-bit keys

### "TypeError: a bytes-like object is required, not 'str'"
**Cause**: Passing string instead of bytes  
**Solution**: Convert strings to bytes: `text.encode('utf-8')`

### "cryptography.exceptions.InvalidKey"
**Cause**: Corrupted or wrong key format  
**Solution**: Regenerate keys using proper methods

### "ImportError: cannot import name 'X' from 'zyracrypt'"
**Cause**: Using wrong import path or outdated package  
**Solution**: Update package and check import paths

### "AttributeError: module 'zyracrypt' has no attribute 'X'"
**Cause**: API change or incorrect usage  
**Solution**: Check API documentation and update code

## 🐛 Debugging Tips

### Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Now run your ZyraCrypt code
```

### Test Individual Components
```python
# Test symmetric encryption separately
from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption

try:
    sym_enc = SymmetricEncryption()
    print("✅ Symmetric encryption module loaded")
except Exception as e:
    print(f"❌ Error loading symmetric encryption: {e}")
```

### Verify Installation
```python
# Check package installation
import pkg_resources
try:
    dist = pkg_resources.get_distribution('zyracrypt')
    print(f"✅ ZyraCrypt {dist.version} installed at {dist.location}")
except pkg_resources.DistributionNotFound:
    print("❌ ZyraCrypt not found")

# Check critical dependencies
required_packages = ['cryptography', 'pynacl', 'argon2-cffi']
for pkg in required_packages:
    try:
        __import__(pkg.replace('-', '_'))
        print(f"✅ {pkg} available")
    except ImportError:
        print(f"❌ {pkg} missing")
```

### Performance Profiling
```python
import cProfile
import pstats

# Profile encryption operation
profiler = cProfile.Profile()
profiler.enable()

# Your ZyraCrypt code here
sym_enc = SymmetricEncryption()
result = sym_enc.encrypt_aes_gcm(key, data)

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative').print_stats(10)
```

## 📞 Getting Help

### Before asking for help:
1. **Check this troubleshooting guide**
2. **Search existing GitHub issues**
3. **Review the documentation**
4. **Try the minimal reproduction example**

### When reporting issues:
1. **Python version**: `python --version`
2. **ZyraCrypt version**: `pip show zyracrypt`
3. **Operating system**: Windows/macOS/Linux version
4. **Full error traceback**: Copy complete error message
5. **Minimal reproduction code**: Simplest code that reproduces the issue

### Where to get help:
- **GitHub Issues**: Bug reports and technical issues
- **GitHub Discussions**: General questions and usage help
- **Documentation**: Comprehensive guides and examples
- **Email**: contact@alqudimi.tech for enterprise support

### Creating minimal reproduction example:
```python
#!/usr/bin/env python3
"""
Minimal reproduction example for ZyraCrypt issue
"""
import os
from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption

def reproduce_issue():
    """Reproduce the issue with minimal code"""
    try:
        sym_enc = SymmetricEncryption()
        key = os.urandom(32)
        data = b"test data"
        
        # The operation that fails
        result = sym_enc.encrypt_aes_gcm(key, data)
        print("✅ Operation successful")
        return result
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    reproduce_issue()
```

---

*This troubleshooting guide is continuously updated based on community feedback. Help us improve it by reporting issues and solutions!*