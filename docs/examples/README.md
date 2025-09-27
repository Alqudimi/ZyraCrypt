# 📚 ZyraCrypt Examples

This directory contains practical examples demonstrating how to use ZyraCrypt's features effectively.

## 📋 Example Categories

### 🔰 Basic Usage
- **[Basic Encryption](basic_encryption.py)** - Simple symmetric and asymmetric encryption
- **[Key Management](key_management.py)** - Key generation, derivation, and storage
- **[API Usage](api_usage.py)** - REST API integration examples

### 🚀 Advanced Features
- **[Post-Quantum Cryptography](post_quantum_examples.py)** - Quantum-resistant algorithms
- **[Hybrid Encryption](hybrid_encryption.py)** - Combining classical and post-quantum
- **[Envelope Encryption](envelope_encryption.py)** - Multi-layer key wrapping

### 🏢 Enterprise Use Cases
- **[Secure File Storage](enterprise_file_storage.py)** - File encryption with metadata
- **[Database Encryption](database_encryption.py)** - Encrypting sensitive database fields
- **[Microservices Security](microservices_security.py)** - Service-to-service encryption

### 📊 Performance & Optimization
- **[Performance Benchmarks](performance_benchmarks.py)** - Speed and throughput testing
- **[Memory Optimization](memory_optimization.py)** - Efficient memory usage patterns

## 🎯 Quick Start Examples

### Simple Text Encryption
```python
from zyracrypt.encryption_system.src.core_cryptography.symmetric_encryption import SymmetricEncryption
import os

# Initialize and encrypt
sym_enc = SymmetricEncryption()
key = os.urandom(32)
message = b"Hello, ZyraCrypt!"

iv, ciphertext, tag = sym_enc.encrypt_aes_gcm(key, message)
decrypted = sym_enc.decrypt_aes_gcm(key, iv, ciphertext, tag)
print(decrypted.decode())  # "Hello, ZyraCrypt!"
```

### Post-Quantum Key Exchange
```python
from zyracrypt.encryption_system.src.post_quantum_cryptography.post_quantum_crypto import PostQuantumCrypto

# Generate quantum-resistant keys
pqc = PostQuantumCrypto()
public_key, private_key = pqc.generate_kem_key_pair()

# Encapsulate secret
ciphertext, shared_secret = pqc.encapsulate_kem(public_key)

# Decapsulate on receiver side
recovered_secret = pqc.decapsulate_kem(private_key, ciphertext)
assert shared_secret == recovered_secret
```

## 📁 File Descriptions

| File | Description | Skill Level |
|------|-------------|-------------|
| `basic_encryption.py` | Simple encryption/decryption examples | Beginner |
| `key_management.py` | Key generation and management | Beginner |
| `api_usage.py` | REST API integration | Intermediate |
| `post_quantum_examples.py` | Quantum-resistant cryptography | Intermediate |
| `hybrid_encryption.py` | Advanced hybrid schemes | Advanced |
| `enterprise_file_storage.py` | Production file encryption | Advanced |
| `performance_benchmarks.py` | Speed testing and optimization | Advanced |

## 🏃‍♂️ Running Examples

### Prerequisites
```bash
# Install ZyraCrypt
pip install zyracrypt

# Or install from source
pip install -e .
```

### Execute Examples
```bash
# Run basic examples
python examples/basic_encryption.py

# Run with specific Python version
python3.11 examples/post_quantum_examples.py

# Run all examples
for file in examples/*.py; do python "$file"; done
```

## 🔧 Example Templates

### Function Template
```python
#!/usr/bin/env python3
"""
ZyraCrypt Example: [Example Name]
Demonstrates: [Key features being shown]
Skill Level: [Beginner/Intermediate/Advanced]
"""

import os
import sys
from zyracrypt.encryption_system.src import [required_modules]

def main():
    """Main example function."""
    print("🔐 ZyraCrypt Example: [Example Name]")
    
    try:
        # Example code here
        print("✅ Example completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

## 🎯 Best Practices Demonstrated

### Security Best Practices
- ✅ Proper key generation using secure random sources
- ✅ Authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- ✅ Secure key derivation (Argon2id, scrypt)
- ✅ Constant-time operations for side-channel resistance
- ✅ Proper error handling without information leakage

### Performance Best Practices
- ✅ Efficient memory usage patterns
- ✅ Optimal algorithm selection based on use case
- ✅ Batch processing for large datasets
- ✅ Hardware acceleration where available

### Code Quality Best Practices
- ✅ Clear error handling and logging
- ✅ Comprehensive input validation
- ✅ Documentation with examples
- ✅ Type hints and mypy compatibility

## 📖 Learning Path

### 1. Start Here (Beginner)
1. **Basic Encryption** - Learn fundamental encryption operations
2. **Key Management** - Understand secure key handling
3. **API Usage** - Integrate with web applications

### 2. Intermediate Concepts
4. **Post-Quantum Examples** - Future-proof your applications
5. **Advanced Key Derivation** - Password-based security
6. **Side-Channel Protection** - Defense against timing attacks

### 3. Advanced Topics
7. **Hybrid Encryption** - Combine multiple algorithms
8. **Enterprise Patterns** - Production deployment strategies
9. **Performance Optimization** - Scale for high-throughput applications

## 🤝 Contributing Examples

Want to add more examples? Please:

1. **Follow the template** provided above
2. **Include comprehensive comments** explaining each step
3. **Add error handling** for robust examples
4. **Test thoroughly** before submitting
5. **Update this README** with your new example

### Example Contribution Checklist
- [ ] Clear, descriptive filename
- [ ] Comprehensive docstring
- [ ] Step-by-step comments
- [ ] Error handling included
- [ ] Performance considerations noted
- [ ] Security best practices followed
- [ ] Tested on multiple platforms

## 🔗 Related Resources

- **[API Documentation](../api.md)** - Complete API reference
- **[User Guide](../user_guide.md)** - Comprehensive usage guide
- **[Security Guide](../security.md)** - Security best practices
- **[Performance Guide](../performance.md)** - Optimization techniques

## 💡 Tips for Learning

1. **Start simple**: Begin with basic examples and gradually progress
2. **Experiment**: Modify examples to understand behavior
3. **Read comments**: Examples include detailed explanations
4. **Check performance**: Use timing decorators to measure speed
5. **Verify security**: Understand the security properties of each example

---

*Happy coding with ZyraCrypt! 🔐*