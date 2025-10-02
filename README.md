# ZyraCrypt 🔒

**Enterprise-Grade Cryptographic Library for Python**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)](https://github.com/yourusername/zyracrypt)

ZyraCrypt is a comprehensive cryptographic library providing enterprise-grade security features including advanced encryption, post-quantum cryptography, key management, threshold signatures, secure enclaves, and more.

## ✨ Features

### 🔐 Core Encryption
- **Symmetric Encryption**: AES-256-GCM, ChaCha20-Poly1305
- **Asymmetric Encryption**: RSA-2048/4096, ECDSA (P-256, P-384, P-521), ECDH
- **Post-Quantum Cryptography**: Kyber (KEM), Dilithium (Signatures)
- **Hybrid Encryption**: Classical + Post-Quantum combined for future-proof security

### 🔑 Key Management
- Advanced key generation with multiple KDFs (Argon2id, Scrypt, PBKDF2)
- Secure key storage with encryption at rest
- Key rotation and versioning
- Envelope encryption with KMS integration
- Hardware Security Module (HSM) support
- Threshold key management

### 🛡️ Advanced Security
- **Threshold Signatures**: Shamir secret sharing with configurable thresholds
- **Multi-Signature Schemes**: Collaborative signing protocols
- **Multi-Party Computation (MPC)**: Secure distributed computations
- **Secure Enclaves**: Software and hardware-backed secure execution
- **Side-Channel Resistance**: Constant-time operations and memory protection
- **Algorithm Agility**: Easy migration between cryptographic algorithms

### 🔒 Password Security
- Modern password hashing (Argon2id, Scrypt, PBKDF2)
- Password strength validation
- Secure password generation
- Breach detection ready

### 🎯 Specialized Features
- Plausible deniability layers
- Steganography for data hiding
- Secure memory zeroing
- File encryption utilities
- Secure session management
- Cryptographic audit logging
- Group end-to-end encryption
- Identity-based encryption (IBE)

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### Install from source

```bash
# Clone the repository
git clone https://github.com/yourusername/zyracrypt.git
cd zyracrypt

# Install in development mode
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

### Dependencies
ZyraCrypt automatically installs the following dependencies:
- `cryptography` - Core cryptographic primitives
- `pynacl` - Modern cryptography (NaCl)
- `argon2-cffi` - Argon2 password hashing
- `liboqs-python` - Post-quantum cryptography
- `flask` & `flask-cors` - API framework
- `pillow` - Image processing for steganography

## 🚀 Quick Start

### Basic Encryption

```python
from core_cryptography.encryption_framework import EncryptionFramework

# Initialize the framework
framework = EncryptionFramework()

# Your data and key
key = b"your-32-byte-key-here-for-aes256"  # 32 bytes for AES-256
data = b"Sensitive information to encrypt"

# Encrypt
algo, iv, ciphertext, tag = framework.encrypt(data, key, "AES-GCM")
print(f"Encrypted with {algo}")

# Decrypt
decrypted = framework.decrypt(algo, key, iv, ciphertext, tag)
print(f"Decrypted: {decrypted.decode()}")
```

### Key Management

```python
from key_management.key_manager import KeyManager

# Initialize key manager
key_manager = KeyManager()

# Generate a secure key from password
password = "MySecurePassword123!"
key_data = key_manager.key_generator.derive_key_from_password(
    password, 
    algorithm="argon2"
)

# Store the key securely
key_manager.key_store.store_key("my_key_id", key_data)

# Retrieve when needed
retrieved_key = key_manager.key_store.retrieve_key("my_key_id")
```

### Threshold Signatures

```python
from advanced_features.threshold_multisig_enhanced import ThresholdECDSA

# Create threshold ECDSA instance
threshold_ecdsa = ThresholdECDSA()

# Setup: 3-of-5 threshold signature scheme
participants = ["alice", "bob", "charlie", "dave", "eve"]
keypair = threshold_ecdsa.generate_threshold_keypair(
    threshold=3,
    total_participants=5,
    participants=participants
)

# Sign a message (need 3 participants)
message = b"Important transaction data"
partial_signatures = []

for i, participant in enumerate(participants[:3]):
    partial_sig = threshold_ecdsa.create_partial_signature(
        keypair, i + 1, message, participant
    )
    partial_signatures.append(partial_sig)

# Combine signatures
final_signature = threshold_ecdsa.combine_partial_signatures(
    keypair, partial_signatures, message
)

# Verify
is_valid = threshold_ecdsa.verify_threshold_signature(
    keypair, final_signature, message
)
print(f"Signature valid: {is_valid}")
```

### Envelope Encryption with KMS

```python
from key_management.envelope_encryption_kms import (
    EnvelopeEncryptionManager, KeyStorageLevel
)

# Initialize manager
manager = EnvelopeEncryptionManager()

# Generate data encryption key
key_id, wrapped_key = manager.generate_data_encryption_key(
    purpose="database_encryption",
    algorithm="AES-256-GCM",
    security_level=KeyStorageLevel.HIGH_SECURITY
)

# Encrypt data with wrapped key
sensitive_data = b"Confidential database records"
encrypted = manager.encrypt_with_wrapped_key(wrapped_key, sensitive_data)

# Decrypt
decrypted = manager.decrypt_with_wrapped_key(wrapped_key, encrypted)
```

## 📚 Documentation

### 🌟 Comprehensive Arabic Documentation

**Complete documentation in Arabic (العربية) covering every aspect of ZyraCrypt:**

📖 **[Start Here: Arabic Documentation Guide →](docs/README_AR.md)**

The Arabic documentation includes 16 comprehensive guides:

#### 🎯 Quick Start
- **[00. Index & Navigation](docs/00-index.md)** - Complete documentation index
- **[01. Getting Started](docs/01-getting-started.md)** - Installation and setup
- **[02. Basic Encryption](docs/02-basic-encryption.md)** - AES, ChaCha20, RSA, ECDSA
- **[03. Key Management](docs/03-key-management.md)** - Secure key handling

#### 🚀 Advanced Features  
- **[04. Advanced Features](docs/04-advanced-features.md)** - Threshold signatures, MPC, side-channel protection
- **[05. Post-Quantum Crypto](docs/05-post-quantum.md)** - Kyber, Dilithium, hybrid encryption
- **[06. Practical Examples](docs/06-examples.md)** - Complete real-world implementations
- **[09. Data Protection](docs/09-data-protection.md)** - Compression, obfuscation, memory handling
- **[10. Specialized Security](docs/10-specialized-security.md)** - File encryption, steganography, secure deletion
- **[11. Blockchain Crypto](docs/11-blockchain-crypto.md)** - Block hashing, PoW, transactions

#### 📖 Reference & Support
- **[07. API Reference](docs/07-api-reference.md)** - Complete API documentation
- **[08. Security Best Practices](docs/08-security-best-practices.md)** - Security guidelines
- **[12. Troubleshooting](docs/12-troubleshooting.md)** - Common issues and solutions
- **[13. FAQ](docs/13-faq.md)** - Frequently asked questions

#### 🛠️ Production
- **[14. Deployment Guide](docs/14-deployment-guide.md)** - AWS, Docker, Kubernetes
- **[15. Performance Optimization](docs/15-performance-optimization.md)** - Speed and efficiency tips

**Coverage**: 100+ practical examples | 200+ pages | Every feature documented

## 🧪 Testing

Run the comprehensive test suite:

```bash
python test_advanced_features.py
```

Test coverage includes:
- ✅ Envelope Encryption & KMS
- ✅ Enhanced KDF & Password schemes
- ✅ Algorithm Agility & Versioning
- ✅ Threshold Signatures & Multisig
- ✅ MPC & Secure Enclaves
- ✅ Side-Channel Resistance
- ⚠️ Hybrid Post-Quantum Cryptography (optional)

**Current Test Results**: 6/7 tests passing (85.7%)

## 🏗️ Project Structure

```
zyracrypt/
├── core_cryptography/       # Core encryption algorithms
│   ├── encryption_framework.py
│   ├── symmetric_encryption.py
│   ├── asymmetric_encryption.py
│   └── algorithm_agility_versioning.py
├── key_management/          # Key generation and management
│   ├── key_manager.py
│   ├── key_generator.py
│   ├── envelope_encryption_kms.py
│   └── enhanced_kdf_password.py
├── advanced_features/       # Advanced cryptographic features
│   ├── threshold_multisig_enhanced.py
│   ├── secure_mpc_enclaves.py
│   ├── hybrid_pqc_enhanced.py
│   └── side_channel_protection.py
├── data_protection/         # Data protection utilities
│   ├── data_protection_manager.py
│   ├── compression_unit.py
│   └── secure_memory_handling.py
├── specialized_security/    # Specialized security features
│   ├── file_encryption_manager.py
│   ├── steganography_unit.py
│   └── secure_session_manager.py
└── post_quantum_cryptography/  # Post-quantum algorithms
    └── post_quantum_cryptography_unit.py
```

## 🔒 Security Features

### Side-Channel Protection
- Constant-time comparisons to prevent timing attacks
- Secure memory zeroing to prevent data leakage
- Protected random number generation

### Algorithm Agility
- Easy migration between cryptographic algorithms
- Version tracking for encrypted data
- Automatic algorithm deprecation detection

### Audit Logging
- Comprehensive cryptographic operation logging
- Tamper-evident audit trails
- Compliance-ready logging formats

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

This library implements cryptographic primitives and should be used with care:

- Always use secure random keys of appropriate length
- Never reuse nonces/IVs with the same key
- Store keys securely and rotate them regularly
- Keep dependencies up to date
- Review the security best practices documentation

## 🙏 Acknowledgments

Built with:
- [cryptography](https://github.com/pyca/cryptography) - Python cryptographic library
- [PyNaCl](https://github.com/pyca/pynacl) - Python binding to libsodium
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) - Post-quantum cryptography

## 📞 Support

For questions, issues, or feature requests:
- Open an issue on [GitHub](https://github.com/yourusername/zyracrypt/issues)
- Check the [documentation](docs/)
- Review the [examples](docs/06-examples.md)

---

**Made with ❤️ by Alqudimi Systems**
