# User Guide

This comprehensive guide provides detailed instructions and examples for using the Advanced Encryption System in your applications.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Basic Encryption Operations](#basic-encryption-operations)
3. [Key Management](#key-management)
4. [Advanced Features](#advanced-features)
5. [REST API Usage](#rest-api-usage)
6. [Best Practices](#best-practices)
7. [Performance Optimization](#performance-optimization)
8. [Troubleshooting](#troubleshooting)

## Getting Started

### Initial Setup

After installation, set up your development environment:

```python
import sys
import os

# Add the encryption system to your Python path
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
sys.path.insert(0, encryption_root)
sys.path.insert(0, encryption_src)

# Import core modules
from core_cryptography.symmetric_encryption import SymmetricEncryption
from core_cryptography.asymmetric_encryption import AsymmetricEncryption
from core_cryptography.encryption_framework import EncryptionFramework
from key_management.key_manager import KeyManager
```

### Your First Encryption

Here's a simple example to encrypt and decrypt data:

```python
# Initialize components
framework = EncryptionFramework()
key = os.urandom(32)  # Generate 256-bit key

# Encrypt
plaintext = b"Hello, Secure World!"
algorithm, iv, ciphertext, tag = framework.encrypt(plaintext, key)

print(f"Algorithm used: {algorithm}")
print(f"Encrypted: {ciphertext.hex()}")

# Decrypt
symmetric = SymmetricEncryption()
decrypted = symmetric.decrypt_aes_gcm(key, iv, ciphertext, tag)
print(f"Decrypted: {decrypted.decode()}")
```

## Basic Encryption Operations

### Symmetric Encryption

#### AES-GCM (Recommended)

AES-GCM provides authenticated encryption, ensuring both confidentiality and integrity:

```python
from core_cryptography.symmetric_encryption import SymmetricEncryption
import os

# Initialize
enc = SymmetricEncryption()

# Generate key and IV
key = os.urandom(32)  # 256-bit key
iv = os.urandom(12)   # 96-bit IV for GCM

# Encrypt
plaintext = b"Confidential business data"
ciphertext, tag = enc.encrypt_aes_gcm(key, iv, plaintext)

# Decrypt
decrypted = enc.decrypt_aes_gcm(key, iv, ciphertext, tag)
assert plaintext == decrypted
```

#### ChaCha20-Poly1305 (Alternative)

For environments without AES hardware acceleration:

```python
# Generate key and nonce
key = os.urandom(32)   # 256-bit key
nonce = os.urandom(12) # 96-bit nonce

# Encrypt
plaintext = b"Mobile application data"
ciphertext, tag = enc.encrypt_chacha20_poly1305(key, nonce, plaintext)

# Decrypt
decrypted = enc.decrypt_chacha20_poly1305(key, nonce, ciphertext, tag)
```

#### Authenticated Encryption with Additional Data (AEAD)

Include additional authenticated data that won't be encrypted:

```python
# Additional data that needs authentication but not encryption
aad = b"user_id:12345,session:abc123"

# Encrypt with AAD
ciphertext, tag = enc.encrypt_aes_gcm(key, iv, plaintext, aad)

# Decrypt with AAD
decrypted = enc.decrypt_aes_gcm(key, iv, ciphertext, tag, aad)
```

### Asymmetric Encryption

#### RSA Encryption

For small data or key exchange:

```python
from core_cryptography.asymmetric_encryption import AsymmetricEncryption

asym = AsymmetricEncryption()

# Generate key pair
private_key, public_key = asym.generate_rsa_key_pair(2048)

# Encrypt (max ~190 bytes for 2048-bit key)
plaintext = b"Symmetric key or small secret"
ciphertext = asym.rsa_encrypt(public_key, plaintext)

# Decrypt
decrypted = asym.rsa_decrypt(private_key, ciphertext)
```

#### Elliptic Curve Cryptography (ECC)

For digital signatures:

```python
# Generate ECC key pair
private_key, public_key = asym.generate_ecdh_key_pair()

# Sign data
message = b"Important document content"
signature = asym.ecdsa_sign(private_key, message)

# Verify signature
is_valid = asym.ecdsa_verify(public_key, message, signature)
print(f"Signature valid: {is_valid}")
```

### Hybrid Encryption

Combine symmetric and asymmetric encryption for best performance:

```python
def hybrid_encrypt(public_key_pem, plaintext):
    """Encrypt large data using hybrid encryption"""
    # Generate symmetric key
    symmetric_key = os.urandom(32)
    iv = os.urandom(12)
    
    # Encrypt data with symmetric key
    enc = SymmetricEncryption()
    ciphertext, tag = enc.encrypt_aes_gcm(symmetric_key, iv, plaintext)
    
    # Encrypt symmetric key with public key
    asym = AsymmetricEncryption()
    encrypted_key = asym.rsa_encrypt(public_key_pem, symmetric_key)
    
    return {
        'encrypted_key': encrypted_key,
        'iv': iv,
        'ciphertext': ciphertext,
        'tag': tag
    }

def hybrid_decrypt(private_key_pem, encrypted_data):
    """Decrypt hybrid encrypted data"""
    asym = AsymmetricEncryption()
    enc = SymmetricEncryption()
    
    # Decrypt symmetric key
    symmetric_key = asym.rsa_decrypt(private_key_pem, encrypted_data['encrypted_key'])
    
    # Decrypt data
    plaintext = enc.decrypt_aes_gcm(
        symmetric_key,
        encrypted_data['iv'],
        encrypted_data['ciphertext'],
        encrypted_data['tag']
    )
    
    return plaintext

# Example usage
asym = AsymmetricEncryption()
private_key, public_key = asym.generate_rsa_key_pair(2048)

large_data = b"This could be a large file or document" * 1000
encrypted = hybrid_encrypt(public_key, large_data)
decrypted = hybrid_decrypt(private_key, encrypted)
assert large_data == decrypted
```

## Key Management

### Using KeyManager

The KeyManager provides secure key storage and lifecycle management:

```python
from key_management.key_manager import KeyManager

# Initialize with custom storage path
key_manager = KeyManager(key_store_path="./my_keys.db")

# Generate and store keys
app_key_id = "application_master_key"
app_key = key_manager.generate_and_store_symmetric_key(app_key_id, 256)

user_key_id = "user_12345_data_key"
user_key = key_manager.generate_and_store_symmetric_key(user_key_id, 256)

# Retrieve keys later
retrieved_key = key_manager.retrieve_key(app_key_id)
assert app_key == retrieved_key
```

### Key Derivation

Derive keys from passwords using modern algorithms:

```python
from key_management.enhanced_kdf_password import EnhancedKDF, KDFAlgorithm
import os

kdf = EnhancedKDF()

# Derive key from password
password = b"user_password_123"
salt = os.urandom(32)  # Store this with the derived key

result = kdf.derive_key(
    password=password,
    salt=salt,
    algorithm=KDFAlgorithm.ARGON2ID,  # Recommended for most use cases
    key_length=32
)

derived_key = result.key
print(f"Key derivation time: {result.timing_info['duration_ms']}ms")
```

### Key Exchange

Secure key exchange using Elliptic Curve Diffie-Hellman:

```python
from key_management.key_exchange import KeyExchange

ke = KeyExchange()

# Party A generates key pair
private_a, public_a = ke.generate_ecdh_key_pair()

# Party B generates key pair
private_b, public_b = ke.generate_ecdh_key_pair()

# Both parties compute shared secret
shared_secret_a = ke.ecdh_key_exchange(private_a, public_b)
shared_secret_b = ke.ecdh_key_exchange(private_b, public_a)

assert shared_secret_a == shared_secret_b
print("Key exchange successful!")

# Derive encryption key from shared secret
from key_management.enhanced_kdf import EnhancedKDF
kdf = EnhancedKDF()
encryption_key = kdf.derive_key(
    password=shared_secret_a,
    salt=b"key_exchange_salt",
    algorithm=KDFAlgorithm.PBKDF2_SHA256,
    key_length=32
).key
```

## Advanced Features

### Post-Quantum Cryptography

Prepare for quantum-resistant security:

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine

pqc = HybridPQCEngine()

# Generate hybrid classical/post-quantum key pair
public_keys, private_keys = pqc.generate_hybrid_keypair()

# Perform hybrid key exchange
key_material = pqc.hybrid_key_exchange(
    receiver_classical_public=public_keys['classical'],
    receiver_pq_public=public_keys['pq']
)

# Receiver decapsulates the key
decapsulated = pqc.hybrid_key_decapsulation(
    private_keys['classical'],
    private_keys['pq'],
    key_material.pq_ciphertext,
    key_material.classical_public_key
)

# Verify shared secrets match
assert key_material.combined_shared_secret == decapsulated.combined_shared_secret
print("Post-quantum key exchange successful!")
```

### Envelope Encryption

Multi-layer key protection for enterprise environments:

```python
from key_management.envelope_encryption_kms import EnvelopeEncryptionManager

envelope_mgr = EnvelopeEncryptionManager()

# Generate data encryption key with wrapping
key_id, wrapped_key = envelope_mgr.generate_data_encryption_key(
    purpose='user_data_encryption',
    algorithm='AES-256-GCM'
)

# Encrypt data with the wrapped key
plaintext = b"Sensitive enterprise data"
encrypted_data = envelope_mgr.encrypt_with_wrapped_key(wrapped_key, plaintext)

# Decrypt data
decrypted = envelope_mgr.decrypt_with_wrapped_key(wrapped_key, encrypted_data)
assert plaintext == decrypted
```

### Threshold Signatures

Distributed signing with m-of-n requirements:

```python
from advanced_features.threshold_multisig_enhanced import MultisigManager

multisig = MultisigManager()

# Create 2-of-3 multisig policy
policy_id = "company_treasury_policy"
policy = multisig.create_multisig_policy(
    policy_id=policy_id,
    threshold=2,
    total_signers=3,
    signature_scheme='ed25519'
)

# Generate key shares for all signers
key_shares = multisig.generate_threshold_keys(policy)

# Sign with first 2 signers
message = b"Transfer $10,000 to account XYZ"
partial_sigs = []
for i in range(2):  # Only need 2 signatures
    partial_sig = multisig.create_partial_signature(
        policy, message, key_shares[i]
    )
    partial_sigs.append(partial_sig)

# Combine signatures
final_signature = multisig.combine_signatures(policy, message, partial_sigs)

# Verify signature
is_valid = multisig.verify_signature(policy, message, final_signature)
print(f"Multisig verification: {is_valid}")
```

### Side-Channel Protection

Constant-time operations for security-critical applications:

```python
from advanced_features.side_channel_protection import TimingAttackProtection

timing_protection = TimingAttackProtection()

# Constant-time comparison
secret_token = b"user_session_token_abc123"
provided_token = b"user_session_token_abc123"

# This comparison takes constant time regardless of input
is_equal = timing_protection.constant_time_compare(secret_token, provided_token)

# Timing-safe HMAC verification
key = os.urandom(32)
hmac_result = timing_protection.timing_safe_hmac_verify(
    secret_token, provided_token, key
)

# Add secure random delay to mask timing patterns
timing_protection.secure_random_delay(1, 5)  # 1-5 seconds
```

## REST API Usage

### Using curl

```bash
# Check system health
curl http://localhost:5000/api/health

# Encrypt text
curl -X POST http://localhost:5000/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello API!", "algorithm": "auto"}'

# Enhanced key derivation
curl -X POST http://localhost:5000/api/enhanced-kdf \
  -H "Content-Type: application/json" \
  -d '{
    "password": "my_password",
    "algorithm": "argon2id",
    "salt_length": 32,
    "key_length": 32
  }'
```

### Python Client

```python
import requests
import json
import base64

class EncryptionAPIClient:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        
    def encrypt_text(self, text, algorithm="auto"):
        """Encrypt text using the API"""
        response = requests.post(
            f"{self.base_url}/api/encrypt",
            json={"text": text, "algorithm": algorithm}
        )
        return response.json()
    
    def decrypt_text(self, encrypted_data, iv, tag, key):
        """Decrypt text using the API"""
        response = requests.post(
            f"{self.base_url}/api/decrypt",
            json={
                "encrypted_data": encrypted_data,
                "iv": iv,
                "tag": tag,
                "key": key
            }
        )
        return response.json()
    
    def derive_key(self, password, algorithm="argon2id"):
        """Derive key from password"""
        response = requests.post(
            f"{self.base_url}/api/enhanced-kdf",
            json={
                "password": password,
                "algorithm": algorithm,
                "salt_length": 32,
                "key_length": 32
            }
        )
        return response.json()

# Example usage
client = EncryptionAPIClient()

# Encrypt
result = client.encrypt_text("Confidential message")
print(f"Encrypted successfully: {result['success']}")

# Decrypt
if result['success']:
    data = result['data']
    decrypted = client.decrypt_text(
        data['encrypted_data'],
        data['iv'],
        data['tag'],
        data['key']
    )
    print(f"Decrypted: {decrypted['decrypted_text']}")
```

## Best Practices

### Security Best Practices

1. **Key Management**
   - Use KeyManager for secure key storage
   - Implement proper key rotation schedules
   - Never hardcode keys in source code
   - Use environment variables for configuration

2. **Algorithm Selection**
   - Use AES-GCM for most symmetric encryption needs
   - Use ECC instead of RSA for new applications
   - Consider post-quantum algorithms for long-term security

3. **Random Number Generation**
   - Always use os.urandom() for cryptographic randomness
   - Never reuse IVs/nonces with the same key
   - Generate sufficient entropy (12 bytes for GCM)

4. **Error Handling**
   - Never expose cryptographic errors to end users
   - Log security events for auditing
   - Implement proper exception handling

### Code Examples

#### Secure File Encryption

```python
def encrypt_file(file_path, output_path, password):
    """Securely encrypt a file with password"""
    # Derive key from password
    kdf = EnhancedKDF()
    salt = os.urandom(32)
    
    key_result = kdf.derive_key(
        password=password.encode(),
        salt=salt,
        algorithm=KDFAlgorithm.ARGON2ID,
        key_length=32
    )
    
    # Encrypt file
    enc = SymmetricEncryption()
    iv = os.urandom(12)
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext, tag = enc.encrypt_aes_gcm(key_result.key, iv, plaintext)
    
    # Write encrypted file with metadata
    with open(output_path, 'wb') as f:
        f.write(salt)  # 32 bytes
        f.write(iv)    # 12 bytes
        f.write(tag)   # 16 bytes
        f.write(ciphertext)
    
    print(f"File encrypted: {output_path}")

def decrypt_file(encrypted_path, output_path, password):
    """Decrypt a password-protected file"""
    with open(encrypted_path, 'rb') as f:
        salt = f.read(32)
        iv = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()
    
    # Derive key
    kdf = EnhancedKDF()
    key_result = kdf.derive_key(
        password=password.encode(),
        salt=salt,
        algorithm=KDFAlgorithm.ARGON2ID,
        key_length=32
    )
    
    # Decrypt
    enc = SymmetricEncryption()
    plaintext = enc.decrypt_aes_gcm(key_result.key, iv, ciphertext, tag)
    
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"File decrypted: {output_path}")

# Usage
encrypt_file("document.pdf", "document.pdf.enc", "strong_password123")
decrypt_file("document.pdf.enc", "document_decrypted.pdf", "strong_password123")
```

#### Secure Database Field Encryption

```python
class FieldEncryptor:
    """Encrypt database fields transparently"""
    
    def __init__(self, key_manager, field_key_id):
        self.key_manager = key_manager
        self.field_key_id = field_key_id
        self.encryption = SymmetricEncryption()
    
    def encrypt_field(self, plaintext):
        """Encrypt a database field value"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        key = self.key_manager.retrieve_key(self.field_key_id)
        iv = os.urandom(12)
        
        ciphertext, tag = self.encryption.encrypt_aes_gcm(key, iv, plaintext)
        
        # Combine IV + tag + ciphertext for storage
        encrypted_blob = iv + tag + ciphertext
        return base64.b64encode(encrypted_blob).decode()
    
    def decrypt_field(self, encrypted_value):
        """Decrypt a database field value"""
        encrypted_blob = base64.b64decode(encrypted_value)
        
        iv = encrypted_blob[:12]
        tag = encrypted_blob[12:28]
        ciphertext = encrypted_blob[28:]
        
        key = self.key_manager.retrieve_key(self.field_key_id)
        plaintext = self.encryption.decrypt_aes_gcm(key, iv, ciphertext, tag)
        
        return plaintext.decode()

# Usage with database models
key_manager = KeyManager()
key_manager.generate_and_store_symmetric_key("user_pii_key", 256)

encryptor = FieldEncryptor(key_manager, "user_pii_key")

# Encrypting before database insert
encrypted_ssn = encryptor.encrypt_field("123-45-6789")
encrypted_email = encryptor.encrypt_field("user@example.com")

# Decrypting after database select
original_ssn = encryptor.decrypt_field(encrypted_ssn)
original_email = encryptor.decrypt_field(encrypted_email)
```

## Performance Optimization

### Algorithm Selection for Performance

```python
import time
import os

def benchmark_algorithms():
    """Compare encryption algorithm performance"""
    enc = SymmetricEncryption()
    data_sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
    
    for size in data_sizes:
        plaintext = os.urandom(size)
        key = os.urandom(32)
        
        print(f"\nBenchmarking {size} bytes:")
        
        # AES-GCM
        iv = os.urandom(12)
        start = time.time()
        for _ in range(1000):
            ciphertext, tag = enc.encrypt_aes_gcm(key, iv, plaintext)
        aes_time = (time.time() - start) * 1000
        print(f"AES-GCM: {aes_time:.2f}ms per 1000 operations")
        
        # ChaCha20-Poly1305
        nonce = os.urandom(12)
        start = time.time()
        for _ in range(1000):
            ciphertext, tag = enc.encrypt_chacha20_poly1305(key, nonce, plaintext)
        chacha_time = (time.time() - start) * 1000
        print(f"ChaCha20-Poly1305: {chacha_time:.2f}ms per 1000 operations")

benchmark_algorithms()
```

### Memory Management

```python
import gc
from advanced_features.side_channel_protection import SideChannelGuard

def secure_memory_handling():
    """Demonstrate secure memory practices"""
    guard = SideChannelGuard()
    
    # Allocate sensitive data
    sensitive_key = os.urandom(32)
    
    try:
        # Use the key for encryption
        enc = SymmetricEncryption()
        plaintext = b"Sensitive data"
        iv = os.urandom(12)
        ciphertext, tag = enc.encrypt_aes_gcm(sensitive_key, iv, plaintext)
        
    finally:
        # Securely zero memory
        guard.secure_zero_memory(sensitive_key)
        
        # Force garbage collection
        gc.collect()
```

## Troubleshooting

### Common Issues and Solutions

#### Import Errors

```python
# If you get import errors, ensure the path is correct
import sys
import os

# Debug: Print current path
print("Current working directory:", os.getcwd())
print("Python path:", sys.path)

# Add encryption system to path
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
if os.path.exists(encryption_root):
    sys.path.insert(0, encryption_root)
    print("✓ Encryption system path added")
else:
    print("✗ Encryption system path not found")
```

#### Key Management Issues

```python
# Test key manager initialization
try:
    key_manager = KeyManager()
    test_key = key_manager.generate_symmetric_key(256)
    print("✓ Key manager working correctly")
except Exception as e:
    print(f"✗ Key manager error: {e}")
```

#### Performance Issues

```python
# Check if AES-NI is available
import cpuinfo

def check_hardware_support():
    """Check for cryptographic hardware support"""
    cpu_info = cpuinfo.get_cpu_info()
    flags = cpu_info.get('flags', [])
    
    print("CPU:", cpu_info.get('brand_raw', 'Unknown'))
    print("AES-NI support:", 'aes' in flags)
    print("RDRAND support:", 'rdrand' in flags)
    
    if 'aes' not in flags:
        print("⚠️  Consider using ChaCha20 for better performance")

check_hardware_support()
```

### Debugging Tips

1. **Enable Debug Logging**
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **Test Individual Components**
   ```python
   # Test each module separately
   def test_components():
       tests = [
           ("Symmetric Encryption", test_symmetric),
           ("Asymmetric Encryption", test_asymmetric),
           ("Key Manager", test_key_manager),
       ]
       
       for name, test_func in tests:
           try:
               test_func()
               print(f"✓ {name}")
           except Exception as e:
               print(f"✗ {name}: {e}")
   ```

3. **Performance Profiling**
   ```python
   import cProfile
   
   def profile_encryption():
       """Profile encryption performance"""
       def encrypt_test():
           enc = SymmetricEncryption()
           key = os.urandom(32)
           data = os.urandom(10240)
           iv = os.urandom(12)
           return enc.encrypt_aes_gcm(key, iv, data)
       
       cProfile.run('encrypt_test()')
   ```

### Getting Help

If you encounter issues not covered in this guide:

1. Check the [Installation Guide](installation.md) for setup issues
2. Review the [API Documentation](api.md) for usage questions
3. Consult the [Security Documentation](security.md) for security concerns
4. Search existing issues in the project repository
5. Create a detailed issue report with:
   - Python version and operating system
   - Complete error messages
   - Minimal code to reproduce the issue
   - Expected vs actual behavior

This user guide provides comprehensive coverage of the Advanced Encryption System's functionality. For the most up-to-date information, always refer to the latest version of this documentation.