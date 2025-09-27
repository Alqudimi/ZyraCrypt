# Installation Guide

This guide provides step-by-step instructions for installing and setting up the Advanced Encryption System.

## System Requirements

### Minimum Requirements
- **Python**: 3.11 or higher
- **Memory**: 512MB RAM
- **Storage**: 100MB available space
- **Network**: Internet connection for package installation

### Recommended Requirements
- **Python**: 3.11+ (latest stable version)
- **Memory**: 2GB RAM for enterprise features
- **Storage**: 500MB available space
- **CPU**: Multi-core processor with AES-NI support for optimal performance

### Platform Support
- **Linux**: Ubuntu 20.04+, CentOS 8+, Debian 11+
- **macOS**: 10.15+ (Catalina or later)
- **Windows**: Windows 10+ (with WSL2 recommended)

## Installation Methods

### Method 1: Standard Installation (Recommended)

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd advanced-encryption-system
   ```

2. **Create Virtual Environment** (Recommended)
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Verify Installation**
   ```bash
   python -c "
   import sys, os
   encryption_root = os.path.join(os.getcwd(), 'alqudimi_encryption_system')
   encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
   sys.path.insert(0, encryption_root)
   sys.path.insert(0, encryption_src)
   from core_cryptography.symmetric_encryption import SymmetricEncryption
   print('✓ Installation successful!')
   "
   ```

   **Note**: This project currently uses path-based imports. For a production deployment, consider packaging the library as an installable Python package.

### Method 2: Development Installation

For developers who want to contribute or modify the system:

1. **Install Development Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-cov black flake8 mypy
   ```

2. **Install Pre-commit Hooks**
   ```bash
   pip install pre-commit
   pre-commit install
   ```

3. **Run Tests**
   ```bash
   python -m pytest tests/ -v
   ```

## Environment Configuration

### Required Environment Variables

Set these environment variables for proper operation:

```bash
# Required: Session secret for Flask application security
export SESSION_SECRET="your-secure-session-secret-here"

# Optional: Database connection (if using database features)
export DATABASE_URL="postgresql://user:pass@localhost/dbname"

# Optional: CORS configuration for API access (defaults to localhost)
export CORS_ORIGINS="http://localhost:*,http://127.0.0.1:*"
```

**Security Notes**: 
- Generate a strong, random SESSION_SECRET (32+ characters)
- For production, restrict CORS_ORIGINS to specific trusted domains
- For Replit or cloud deployments, these are typically configured automatically

### Optional Configuration

```bash
# Performance tuning
export OMP_NUM_THREADS=4
export PYTHONHASHSEED=random

# Logging level
export LOG_LEVEL=INFO
```

## Dependency Details

### Core Dependencies
- **cryptography**: Modern cryptographic recipes and primitives
- **flask**: Web framework for REST API
- **flask-cors**: Cross-Origin Resource Sharing support
- **argon2-cffi**: Secure password hashing
- **pynacl**: Modern cryptographic library

### Advanced Dependencies
- **liboqs-python**: Post-quantum cryptography algorithms
- **pqcrypto**: Additional quantum-resistant algorithms
- **quantcrypt**: Advanced quantum cryptography features
- **boto3**: AWS integration for cloud KMS
- **psycopg2-binary**: PostgreSQL database support

### Build Dependencies
- **cython**: For performance-critical components
- **setuptools**: Package building
- **wheel**: Binary package format

## Troubleshooting

### Common Installation Issues

#### Issue: `liboqs-python` Installation Fails

**Solution for Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install cmake libssl-dev build-essential
pip install liboqs-python
```

**Solution for macOS:**
```bash
brew install cmake openssl
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
pip install liboqs-python
```

**Solution for Windows:**
```bash
# Install Visual Studio Build Tools
# Install CMake from https://cmake.org/
pip install liboqs-python
```

#### Issue: Permission Errors

**Solution:**
```bash
# Use user installation
pip install --user -r requirements.txt
```

#### Issue: SSL Certificate Errors

**Solution:**
```bash
pip install --trusted-host pypi.org --trusted-host pypi.python.org -r requirements.txt
```

### Performance Optimization

#### Enable Hardware Acceleration

1. **Verify AES-NI Support:**
   ```bash
   python -c "
   import cpuinfo
   info = cpuinfo.get_cpu_info()
   print('AES-NI supported:', 'aes' in info.get('flags', []))
   "
   ```

2. **Install optimized cryptography:**
   ```bash
   pip install --upgrade cryptography
   ```

#### Memory Optimization

For memory-constrained environments:
```bash
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1
```

## Verification Steps

### Basic Functionality Test

```python
#!/usr/bin/env python3
"""
Installation verification script
"""
import sys
import os

# Add encryption system to path
sys.path.insert(0, 'alqudimi_encryption_system/encryption_system/src')

def test_basic_encryption():
    """Test basic encryption functionality"""
    try:
        from core_cryptography.symmetric_encryption import SymmetricEncryption
        
        # Initialize encryption
        enc = SymmetricEncryption()
        
        # Test AES-GCM
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"Test message"
        
        ciphertext, tag = enc.encrypt_aes_gcm(key, iv, plaintext)
        decrypted = enc.decrypt_aes_gcm(key, iv, ciphertext, tag)
        
        assert plaintext == decrypted
        print("✓ AES-GCM encryption test passed")
        
    except Exception as e:
        print(f"✗ Basic encryption test failed: {e}")
        return False
    
    return True

def test_advanced_features():
    """Test advanced encryption features"""
    try:
        from key_management.enhanced_kdf_password import EnhancedKDF
        
        kdf = EnhancedKDF()
        result = kdf.derive_key(
            password=b"test_password",
            salt=os.urandom(32),
            algorithm="argon2id",
            key_length=32
        )
        
        assert len(result.key) == 32
        print("✓ Enhanced KDF test passed")
        
    except Exception as e:
        print(f"✗ Advanced features test failed: {e}")
        return False
    
    return True

def test_api_server():
    """Test Flask API server"""
    try:
        import requests
        from threading import Thread
        import time
        
        # Start server in background
        from app import app
        
        def run_server():
            app.run(host='localhost', port=5001, debug=False)
        
        server_thread = Thread(target=run_server, daemon=True)
        server_thread.start()
        time.sleep(2)  # Allow server to start
        
        # Test health endpoint
        response = requests.get('http://localhost:5001/api/health', timeout=5)
        assert response.status_code == 200
        print("✓ API server test passed")
        
    except Exception as e:
        print(f"✗ API server test failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("Running installation verification tests...\n")
    
    tests = [
        ("Basic Encryption", test_basic_encryption),
        ("Advanced Features", test_advanced_features),
        ("API Server", test_api_server),
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        print(f"Testing {name}...")
        if test_func():
            passed += 1
        print()
    
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 Installation verification completed successfully!")
        print("The Advanced Encryption System is ready for use.")
    else:
        print("⚠️  Some tests failed. Please check the installation.")
        sys.exit(1)
```

### Performance Benchmark

Run the performance test to verify optimal configuration:

```bash
python test_library.py
```

This will output performance metrics and verify all components are working correctly.

## Next Steps

After successful installation:

1. **Read the User Guide**: [docs/user_guide.md](user_guide.md)
2. **Review Security Documentation**: [docs/security.md](security.md)
3. **Explore API Documentation**: [docs/api.md](api.md)
4. **Run the Flask API Server**: `python main.py`

## Getting Help

If you encounter issues during installation:

1. Check the [troubleshooting section](#troubleshooting) above
2. Review system requirements and dependencies
3. Search existing issues in the project repository
4. Create a new issue with detailed error information

Remember to include:
- Operating system and version
- Python version
- Complete error message
- Steps to reproduce the issue