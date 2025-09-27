# Examples and Tutorials

This document provides comprehensive examples and tutorials for using the Advanced Encryption System in various scenarios.

## Table of Contents

1. [Basic Examples](#basic-examples)
2. [Advanced Usage](#advanced-usage)
3. [Enterprise Features](#enterprise-features)
4. [Integration Examples](#integration-examples)
5. [Performance Optimization](#performance-optimization)
6. [Real-World Scenarios](#real-world-scenarios)

## Basic Examples

### 1. Simple Text Encryption

```python
import os
import sys

# Setup library path
encryption_root = os.path.join(os.path.dirname(__file__), 'alqudimi_encryption_system')
encryption_src = os.path.join(encryption_root, 'encryption_system', 'src')
sys.path.insert(0, encryption_root)
sys.path.insert(0, encryption_src)

from core_cryptography.symmetric_encryption import SymmetricEncryption
from core_cryptography.encryption_framework import EncryptionFramework

def simple_text_encryption():
    """Basic text encryption example."""
    # Initialize components
    framework = EncryptionFramework()
    symmetric = SymmetricEncryption()
    
    # Generate secure key
    key = os.urandom(32)  # 256-bit key
    
    # Text to encrypt
    message = "This is a confidential message!"
    plaintext = message.encode('utf-8')
    
    # Encrypt
    algorithm, iv, ciphertext, tag = framework.encrypt(plaintext, key)
    print(f"Algorithm: {algorithm}")
    print(f"Encrypted: {ciphertext.hex()}")
    
    # Decrypt
    decrypted = symmetric.decrypt_aes_gcm(key, iv, ciphertext, tag)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    
    return True

if __name__ == "__main__":
    simple_text_encryption()
```

### 2. File Encryption

```python
from specialized_security.file_encryption_manager import FileEncryptionManager

def encrypt_file_example():
    """Encrypt and decrypt a file."""
    file_crypto = FileEncryptionManager()
    
    # Generate file encryption key
    file_key = file_crypto.generate_file_key()
    
    # Original file content
    original_data = b"This is sensitive file content that needs protection."
    
    # Encrypt file data
    encrypted_package = file_crypto.encrypt_file_data(original_data, file_key)
    
    print(f"Original size: {len(original_data)} bytes")
    print(f"Encrypted size: {len(encrypted_package.ciphertext)} bytes")
    print(f"Compression ratio: {encrypted_package.compression_ratio:.2f}")
    
    # Decrypt file data
    decrypted_data = file_crypto.decrypt_file_data(encrypted_package, file_key)
    
    assert decrypted_data == original_data
    print("✓ File encryption/decryption successful!")
    
    return encrypted_package

encrypt_file_example()
```

### 3. Key Generation and Management

```python
from key_management.key_manager import KeyManager
from key_management.key_generator import KeyGenerator

def key_management_example():
    """Demonstrate key generation and management."""
    key_manager = KeyManager()
    key_generator = KeyGenerator()
    
    # Generate different types of keys
    symmetric_key = key_generator.generate_symmetric_key(256)  # AES-256
    rsa_keypair = key_generator.generate_rsa_keypair(2048)
    ecc_keypair = key_generator.generate_ecc_keypair("secp256r1")
    
    print(f"Symmetric key length: {len(symmetric_key)} bytes")
    print(f"RSA public key size: {rsa_keypair.public_key.key_size} bits")
    print(f"ECC curve: {ecc_keypair.private_key.curve.name}")
    
    # Key derivation
    master_key = os.urandom(32)
    salt = os.urandom(16)
    derived_key = key_manager.derive_key(master_key, salt, 32)
    
    print(f"Derived key: {derived_key.hex()}")
    
    return {
        'symmetric': symmetric_key,
        'rsa': rsa_keypair,
        'ecc': ecc_keypair,
        'derived': derived_key
    }

keys = key_management_example()
```

## Advanced Usage

### 4. Asymmetric Encryption with Digital Signatures

```python
from core_cryptography.asymmetric_encryption import AsymmetricEncryption

def asymmetric_crypto_example():
    """Advanced asymmetric cryptography example."""
    async_crypto = AsymmetricEncryption()
    
    # Generate RSA key pair
    private_key, public_key = async_crypto.generate_rsa_keypair(2048)
    
    # Message to encrypt and sign
    message = b"Important business document requiring both encryption and authentication."
    
    # Encrypt with public key
    encrypted_data = async_crypto.encrypt_rsa_oaep(public_key, message)
    print(f"Encrypted data length: {len(encrypted_data)} bytes")
    
    # Sign with private key
    signature = async_crypto.sign_rsa_pss(private_key, message)
    print(f"Signature length: {len(signature)} bytes")
    
    # Decrypt with private key
    decrypted_data = async_crypto.decrypt_rsa_oaep(private_key, encrypted_data)
    
    # Verify signature with public key
    is_valid = async_crypto.verify_rsa_pss(public_key, message, signature)
    
    print(f"Decryption successful: {decrypted_data == message}")
    print(f"Signature valid: {is_valid}")
    
    return {
        'encrypted': encrypted_data,
        'signature': signature,
        'verified': is_valid
    }

result = asymmetric_crypto_example()
```

### 5. Data Protection with Compression and Obfuscation

```python
from data_protection.data_protection_manager import DataProtectionManager

def data_protection_example():
    """Comprehensive data protection example."""
    data_manager = DataProtectionManager()
    
    # Sample data with different characteristics
    text_data = "This is a sample text document with repeated patterns. " * 100
    binary_data = os.urandom(1024)  # Random binary data
    
    # Protect text data (should compress well)
    protected_text = data_manager.protect_data(
        text_data.encode('utf-8'),
        compression_level=6,
        obfuscation_enabled=True
    )
    
    print(f"Text data - Original: {len(text_data)} bytes")
    print(f"Text data - Protected: {len(protected_text.protected_data)} bytes")
    print(f"Text compression ratio: {protected_text.compression_ratio:.3f}")
    
    # Protect binary data (won't compress much)
    protected_binary = data_manager.protect_data(
        binary_data,
        compression_level=3,
        obfuscation_enabled=True
    )
    
    print(f"Binary data - Original: {len(binary_data)} bytes")
    print(f"Binary data - Protected: {len(protected_binary.protected_data)} bytes")
    print(f"Binary compression ratio: {protected_binary.compression_ratio:.3f}")
    
    # Restore data
    restored_text = data_manager.restore_data(protected_text)
    restored_binary = data_manager.restore_data(protected_binary)
    
    # Verify integrity
    assert restored_text == text_data.encode('utf-8')
    assert restored_binary == binary_data
    
    print("✓ Data protection and restoration successful!")
    
    return {
        'text': protected_text,
        'binary': protected_binary
    }

protection_result = data_protection_example()
```

## Enterprise Features

### 6. Enhanced Password-Based Key Derivation

```python
from key_management.enhanced_kdf_password import EnhancedKDF, KDFAlgorithm, SecurityProfile

def enhanced_kdf_example():
    """Demonstrate enhanced KDF with different security profiles."""
    kdf = EnhancedKDF()
    
    password = "MySecurePassword123!"
    salt = os.urandom(32)
    
    # Different security profiles for different use cases
    profiles = [
        (SecurityProfile.INTERACTIVE, "Interactive login"),
        (SecurityProfile.SENSITIVE, "Sensitive data protection"),
        (SecurityProfile.NON_INTERACTIVE, "Batch processing")
    ]
    
    results = {}
    
    for profile, description in profiles:
        print(f"\n{description} ({profile.name}):")
        
        # Derive key with Argon2id
        result = kdf.derive_key(
            password.encode('utf-8'),
            salt,
            KDFAlgorithm.ARGON2ID,
            key_length=32,
            security_profile=profile
        )
        
        print(f"  Algorithm: {result.algorithm}")
        print(f"  Time cost: {result.time_cost}")
        print(f"  Memory cost: {result.memory_cost}")
        print(f"  Key: {result.key.hex()[:32]}...")
        
        results[profile.name] = result
    
    return results

kdf_results = enhanced_kdf_example()
```

### 7. Envelope Encryption with KMS

```python
from key_management.envelope_encryption_kms import EnvelopeEncryptionManager

def envelope_encryption_example():
    """Demonstrate envelope encryption pattern."""
    envelope_manager = EnvelopeEncryptionManager()
    
    # Large data to encrypt
    large_data = b"Large dataset contents..." * 1000
    
    # Generate and wrap data encryption key
    key_id, wrapped_key = envelope_manager.generate_data_encryption_key(
        purpose="document_encryption",
        algorithm="AES-256-GCM"
    )
    
    print(f"Generated DEK with key ID: {key_id}")
    print(f"Wrapped key size: {len(wrapped_key.wrapped_key)} bytes")
    
    # Encrypt data with the wrapped key
    encrypted_data = envelope_manager.encrypt_with_wrapped_key(wrapped_key, large_data)
    
    print(f"Original data: {len(large_data)} bytes")
    print(f"Encrypted data: {len(encrypted_data['ciphertext'])} bytes")
    
    # Decrypt data
    decrypted_data = envelope_manager.decrypt_with_wrapped_key(
        wrapped_key,
        encrypted_data['ciphertext'],
        encrypted_data['iv'],
        encrypted_data['tag']
    )
    
    assert decrypted_data == large_data
    print("✓ Envelope encryption/decryption successful!")
    
    return {
        'key_id': key_id,
        'wrapped_key': wrapped_key,
        'encrypted_size': len(encrypted_data['ciphertext'])
    }

envelope_result = envelope_encryption_example()
```

### 8. Threshold Signatures (m-of-n)

```python
from advanced_features.threshold_multisig_enhanced import MultisigManager

def threshold_signature_example():
    """Demonstrate threshold signature scheme."""
    multisig = MultisigManager()
    
    # Create multisig policy (2-of-3)
    policy_id = "corporate-treasury-policy"
    policy = multisig.create_multisig_policy(
        policy_id=policy_id,
        threshold=2,
        total_signers=3,
        signature_scheme="ed25519"
    )
    
    print(f"Created policy: {policy.policy_id}")
    print(f"Threshold: {policy.threshold} of {policy.total_signers}")
    
    # Generate threshold keys for all signers
    key_shares = multisig.generate_threshold_keys(policy)
    print(f"Generated {len(key_shares)} key shares")
    
    # Document to sign
    document = b"Treasury transfer: $1,000,000 to Account #12345"
    
    # Create partial signatures (only need 2 out of 3)
    partial_sigs = []
    for i in [0, 2]:  # Use signers 0 and 2 (skip signer 1)
        partial_sig = multisig.create_partial_signature(
            policy, document, key_shares[i]
        )
        partial_sigs.append(partial_sig)
        print(f"Signer {i} created partial signature")
    
    # Combine signatures to create final signature
    final_signature = multisig.combine_signatures(policy, document, partial_sigs)
    
    # Verify the final signature
    is_valid = multisig.verify_signature(policy, document, final_signature)
    
    print(f"Final signature valid: {is_valid}")
    print(f"Signature size: {len(final_signature.signature_data)} bytes")
    
    return {
        'policy': policy,
        'signature': final_signature,
        'valid': is_valid
    }

threshold_result = threshold_signature_example()
```

## Integration Examples

### 9. Flask Web Application Integration

```python
from flask import Flask, request, jsonify
import json
import base64

app = Flask(__name__)

# Initialize encryption components
from core_cryptography.encryption_framework import EncryptionFramework
framework = EncryptionFramework()

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """Encrypt data via REST API."""
    try:
        data = request.get_json()
        
        # Validate input
        if not data or 'text' not in data:
            return jsonify({'error': 'Missing text field'}), 400
        
        plaintext = data['text'].encode('utf-8')
        key = os.urandom(32)  # In production, use proper key management
        
        # Encrypt data
        algorithm, iv, ciphertext, tag = framework.encrypt(plaintext, key)
        
        # Return encrypted data (base64 encoded)
        response = {
            'success': True,
            'algorithm': algorithm,
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(iv).decode(),
            'tag': base64.b64encode(tag).decode(),
            'key_id': 'demo-key-' + os.urandom(8).hex()
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'Advanced Encryption System',
        'version': '2.0.0'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### 10. Database Integration with Encrypted Storage

```python
import sqlite3
import json
from core_cryptography.encryption_framework import EncryptionFramework

class EncryptedDatabase:
    """Database wrapper with transparent encryption."""
    
    def __init__(self, db_path: str, master_key: bytes):
        self.db_path = db_path
        self.master_key = master_key
        self.framework = EncryptionFramework()
        self.conn = sqlite3.connect(db_path)
        self._create_tables()
    
    def _create_tables(self):
        """Create encrypted storage table."""
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS encrypted_data (
                id INTEGER PRIMARY KEY,
                key_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                iv BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                tag BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()
    
    def store_encrypted(self, data: str, key_id: str = None) -> int:
        """Store data with encryption."""
        if key_id is None:
            key_id = f"auto-{os.urandom(8).hex()}"
        
        plaintext = data.encode('utf-8')
        algorithm, iv, ciphertext, tag = self.framework.encrypt(plaintext, self.master_key)
        
        cursor = self.conn.execute(
            '''INSERT INTO encrypted_data 
               (key_id, algorithm, iv, ciphertext, tag) 
               VALUES (?, ?, ?, ?, ?)''',
            (key_id, algorithm, iv, ciphertext, tag)
        )
        self.conn.commit()
        
        return cursor.lastrowid
    
    def retrieve_decrypted(self, record_id: int) -> str:
        """Retrieve and decrypt data."""
        cursor = self.conn.execute(
            '''SELECT algorithm, iv, ciphertext, tag 
               FROM encrypted_data WHERE id = ?''',
            (record_id,)
        )
        
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Record {record_id} not found")
        
        algorithm, iv, ciphertext, tag = row
        
        # For this example, assume AES-GCM
        from core_cryptography.symmetric_encryption import SymmetricEncryption
        symmetric = SymmetricEncryption()
        decrypted = symmetric.decrypt_aes_gcm(self.master_key, iv, ciphertext, tag)
        
        return decrypted.decode('utf-8')

# Example usage
def database_integration_example():
    """Demonstrate encrypted database storage."""
    master_key = os.urandom(32)
    db = EncryptedDatabase(':memory:', master_key)
    
    # Store some encrypted data
    sensitive_data = [
        "User credit card: 4532-1234-5678-9012",
        "Social security: 123-45-6789",
        "Medical record: Patient has condition XYZ"
    ]
    
    record_ids = []
    for data in sensitive_data:
        record_id = db.store_encrypted(data)
        record_ids.append(record_id)
        print(f"Stored record {record_id}")
    
    # Retrieve and decrypt data
    for record_id in record_ids:
        decrypted = db.retrieve_decrypted(record_id)
        print(f"Record {record_id}: {decrypted}")
    
    return db

encrypted_db = database_integration_example()
```

## Performance Optimization

### 11. Bulk Encryption with Performance Monitoring

```python
import time
from typing import List, Tuple

def bulk_encryption_benchmark():
    """Benchmark bulk encryption operations."""
    framework = EncryptionFramework()
    
    # Generate test data of different sizes
    test_sizes = [1024, 10*1024, 100*1024, 1024*1024]  # 1KB, 10KB, 100KB, 1MB
    key = os.urandom(32)
    
    results = []
    
    for size in test_sizes:
        data = os.urandom(size)
        iterations = max(1, 1000 // (size // 1024))  # Fewer iterations for larger data
        
        # Benchmark encryption
        start_time = time.time()
        for _ in range(iterations):
            algorithm, iv, ciphertext, tag = framework.encrypt(data, key)
        end_time = time.time()
        
        total_time = end_time - start_time
        ops_per_second = iterations / total_time
        bytes_per_second = (size * iterations) / total_time
        
        result = {
            'size': size,
            'iterations': iterations,
            'total_time': total_time,
            'ops_per_second': ops_per_second,
            'mbps': bytes_per_second / (1024 * 1024)
        }
        
        results.append(result)
        
        print(f"Size: {size:>8} bytes | "
              f"Ops/sec: {ops_per_second:>8.2f} | "
              f"Throughput: {result['mbps']:>8.2f} MB/s")
    
    return results

print("Performance Benchmark Results:")
print("=" * 60)
benchmark_results = bulk_encryption_benchmark()
```

### 12. Memory-Efficient Streaming Encryption

```python
from typing import Iterator

def streaming_encryption_example():
    """Demonstrate memory-efficient streaming encryption."""
    
    def encrypt_stream(data_stream: Iterator[bytes], key: bytes, chunk_size: int = 8192):
        """Encrypt data stream in chunks."""
        symmetric = SymmetricEncryption()
        
        # Initialize encryption context
        iv = os.urandom(12)  # GCM IV
        yield iv  # First yield the IV
        
        # Process chunks
        for chunk in data_stream:
            if len(chunk) == 0:
                break
            
            # For this example, encrypt each chunk independently
            # In production, you'd use a streaming mode
            ciphertext, tag = symmetric.encrypt_aes_gcm(key, iv, chunk)
            yield ciphertext + tag  # Combine ciphertext and tag
    
    def large_data_generator(total_size: int, chunk_size: int = 8192):
        """Generate large amounts of test data."""
        remaining = total_size
        while remaining > 0:
            current_chunk = min(chunk_size, remaining)
            yield os.urandom(current_chunk)
            remaining -= current_chunk
    
    # Simulate encrypting a 10MB file in streaming fashion
    total_size = 10 * 1024 * 1024  # 10MB
    key = os.urandom(32)
    
    print(f"Streaming encryption of {total_size // (1024*1024)}MB data...")
    
    start_time = time.time()
    
    # Create data generator
    data_gen = large_data_generator(total_size)
    
    # Encrypt in streaming fashion
    encrypted_chunks = []
    for encrypted_chunk in encrypt_stream(data_gen, key):
        encrypted_chunks.append(encrypted_chunk)
    
    end_time = time.time()
    
    total_encrypted_size = sum(len(chunk) for chunk in encrypted_chunks)
    processing_time = end_time - start_time
    throughput = total_size / processing_time / (1024 * 1024)
    
    print(f"Processing time: {processing_time:.2f} seconds")
    print(f"Throughput: {throughput:.2f} MB/s")
    print(f"Memory overhead: {(total_encrypted_size - total_size) / total_size * 100:.2f}%")
    
    return {
        'chunks': len(encrypted_chunks),
        'throughput': throughput,
        'overhead': (total_encrypted_size - total_size) / total_size
    }

streaming_result = streaming_encryption_example()
```

## Real-World Scenarios

### 13. Secure Communication Protocol

```python
from advanced_features.secure_messaging_protocol import SecureMessagingProtocol

def secure_messaging_example():
    """Implement end-to-end encrypted messaging."""
    
    # Initialize messaging for two parties
    alice = SecureMessagingProtocol("alice")
    bob = SecureMessagingProtocol("bob")
    
    # Key exchange (simplified - in reality, use proper key exchange)
    alice_public, alice_private = alice.generate_identity_keypair()
    bob_public, bob_private = bob.generate_identity_keypair()
    
    # Exchange public keys
    alice.add_contact("bob", bob_public)
    bob.add_contact("alice", alice_public)
    
    # Alice sends message to Bob
    message = "Meet me at the coffee shop at 3 PM. Project Alpha is approved."
    
    # Encrypt message
    encrypted_message = alice.encrypt_message("bob", message.encode('utf-8'))
    
    print(f"Original message: {message}")
    print(f"Encrypted size: {len(encrypted_message.ciphertext)} bytes")
    print(f"Sender verification: {encrypted_message.sender_id}")
    
    # Bob receives and decrypts message
    decrypted_message = bob.decrypt_message("alice", encrypted_message)
    
    print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
    print(f"Message integrity verified: {decrypted_message is not None}")
    
    # Bob replies
    reply = "Confirmed. See you at 3 PM."
    encrypted_reply = bob.encrypt_message("alice", reply.encode('utf-8'))
    decrypted_reply = alice.decrypt_message("bob", encrypted_reply)
    
    print(f"Bob's reply: {decrypted_reply.decode('utf-8')}")
    
    return {
        'alice': alice,
        'bob': bob,
        'message_exchange': True
    }

messaging_result = secure_messaging_example()
```

### 14. Document Security with Digital Rights Management

```python
def document_drm_example():
    """Implement document DRM with access control."""
    
    class SecureDocument:
        def __init__(self, content: str, owner: str):
            self.content = content
            self.owner = owner
            self.access_policies = {}
            self.audit_log = []
            
            # Encrypt document content
            self.document_key = os.urandom(32)
            framework = EncryptionFramework()
            plaintext = content.encode('utf-8')
            
            self.algorithm, self.iv, self.ciphertext, self.tag = framework.encrypt(
                plaintext, self.document_key
            )
            
            # Clear plaintext from memory
            del content, plaintext
        
        def grant_access(self, user: str, permissions: List[str], expires: int = None):
            """Grant access to a user with specific permissions."""
            self.access_policies[user] = {
                'permissions': permissions,
                'expires': expires,
                'granted_at': time.time()
            }
            
            self.audit_log.append({
                'action': 'access_granted',
                'user': user,
                'permissions': permissions,
                'timestamp': time.time()
            })
        
        def revoke_access(self, user: str):
            """Revoke user access."""
            if user in self.access_policies:
                del self.access_policies[user]
                
                self.audit_log.append({
                    'action': 'access_revoked',
                    'user': user,
                    'timestamp': time.time()
                })
        
        def access_document(self, user: str, action: str):
            """Access document with permission checking."""
            # Check access policy
            if user not in self.access_policies:
                raise PermissionError(f"User {user} has no access to this document")
            
            policy = self.access_policies[user]
            
            # Check expiration
            if policy.get('expires') and time.time() > policy['expires']:
                raise PermissionError(f"Access expired for user {user}")
            
            # Check permissions
            if action not in policy['permissions']:
                raise PermissionError(f"User {user} not permitted to {action}")
            
            # Log access
            self.audit_log.append({
                'action': f'document_{action}',
                'user': user,
                'timestamp': time.time()
            })
            
            # Decrypt and return content for read operations
            if action == 'read':
                symmetric = SymmetricEncryption()
                decrypted = symmetric.decrypt_aes_gcm(
                    self.document_key, self.iv, self.ciphertext, self.tag
                )
                return decrypted.decode('utf-8')
            
            return True
    
    # Create secure document
    sensitive_doc = SecureDocument(
        "CONFIDENTIAL: Q4 financial projections and strategic initiatives.",
        "ceo@company.com"
    )
    
    # Grant different access levels
    sensitive_doc.grant_access("cfo@company.com", ["read", "print"], expires=time.time() + 86400)
    sensitive_doc.grant_access("analyst@company.com", ["read"], expires=time.time() + 3600)
    sensitive_doc.grant_access("intern@company.com", [], expires=time.time() + 300)
    
    # Test access scenarios
    try:
        # CFO can read
        content = sensitive_doc.access_document("cfo@company.com", "read")
        print(f"CFO accessed: {content[:50]}...")
        
        # Analyst can read but not print
        content = sensitive_doc.access_document("analyst@company.com", "read")
        print("Analyst successfully read document")
        
        try:
            sensitive_doc.access_document("analyst@company.com", "print")
        except PermissionError as e:
            print(f"Analyst print denied: {e}")
        
        # Intern has no permissions
        try:
            sensitive_doc.access_document("intern@company.com", "read")
        except PermissionError as e:
            print(f"Intern access denied: {e}")
        
    except Exception as e:
        print(f"Access error: {e}")
    
    # Show audit log
    print("\nAudit Log:")
    for entry in sensitive_doc.audit_log:
        print(f"  {entry['timestamp']:.0f}: {entry['action']} by {entry['user']}")
    
    return sensitive_doc

secure_doc = document_drm_example()
```

### 15. Crypto-Wallet Security Implementation

```python
def crypto_wallet_example():
    """Implement basic cryptocurrency wallet security."""
    
    class CryptoWallet:
        def __init__(self, password: str):
            # Generate wallet encryption key from password
            from key_management.enhanced_kdf_password import EnhancedKDF, KDFAlgorithm
            kdf = EnhancedKDF()
            
            self.salt = os.urandom(32)
            kdf_result = kdf.derive_key(
                password.encode('utf-8'),
                self.salt,
                KDFAlgorithm.ARGON2ID,
                key_length=32
            )
            self.wallet_key = kdf_result.key
            
            # Generate master private key
            self.master_private_key = os.urandom(32)
            
            # Encrypt master key
            symmetric = SymmetricEncryption()
            iv = os.urandom(12)
            self.encrypted_master_key, self.master_key_tag = symmetric.encrypt_aes_gcm(
                self.wallet_key, iv, self.master_private_key
            )
            self.master_key_iv = iv
            
            # Generate addresses (simplified)
            self.addresses = {}
            self.balances = {}
            
            # Clear sensitive data
            del password
        
        def unlock_wallet(self, password: str) -> bool:
            """Unlock wallet with password."""
            try:
                # Derive key from password
                from key_management.enhanced_kdf_password import EnhancedKDF, KDFAlgorithm
                kdf = EnhancedKDF()
                
                kdf_result = kdf.derive_key(
                    password.encode('utf-8'),
                    self.salt,
                    KDFAlgorithm.ARGON2ID,
                    key_length=32
                )
                test_key = kdf_result.key
                
                # Try to decrypt master key
                symmetric = SymmetricEncryption()
                decrypted_master = symmetric.decrypt_aes_gcm(
                    test_key, self.master_key_iv, 
                    self.encrypted_master_key, self.master_key_tag
                )
                
                # Verify it matches
                return decrypted_master == self.master_private_key
                
            except Exception:
                return False
        
        def generate_address(self, label: str) -> str:
            """Generate new receiving address."""
            if not hasattr(self, 'unlocked') or not self.unlocked:
                raise RuntimeError("Wallet must be unlocked")
            
            # Simplified address generation
            address_seed = self.master_private_key + label.encode('utf-8')
            address_hash = hashlib.sha256(address_seed).hexdigest()
            address = f"bc1{address_hash[:32]}"  # Simplified Bitcoin address
            
            self.addresses[label] = address
            self.balances[address] = 0.0
            
            return address
        
        def create_transaction(self, to_address: str, amount: float, from_label: str):
            """Create and sign transaction."""
            if not hasattr(self, 'unlocked') or not self.unlocked:
                raise RuntimeError("Wallet must be unlocked")
            
            from_address = self.addresses.get(from_label)
            if not from_address:
                raise ValueError(f"Address label {from_label} not found")
            
            if self.balances[from_address] < amount:
                raise ValueError("Insufficient balance")
            
            # Create transaction (simplified)
            transaction_data = {
                'from': from_address,
                'to': to_address,
                'amount': amount,
                'timestamp': time.time(),
                'nonce': os.urandom(8).hex()
            }
            
            # Sign transaction
            tx_bytes = json.dumps(transaction_data, sort_keys=True).encode('utf-8')
            
            # Use asymmetric crypto for signing
            asymmetric = AsymmetricEncryption()
            
            # Generate signing key from master key
            signing_seed = self.master_private_key + from_address.encode('utf-8')
            signing_key_data = hashlib.sha256(signing_seed).digest()
            
            # For this example, create a simplified signature
            signature = hashlib.sha256(tx_bytes + signing_key_data).hexdigest()
            
            transaction_data['signature'] = signature
            
            return transaction_data
    
    # Example usage
    print("Creating secure crypto wallet...")
    
    # Create wallet with strong password
    wallet_password = "MyVerySecureWalletPassword123!@#"
    wallet = CryptoWallet(wallet_password)
    
    # Unlock wallet
    wallet.unlocked = wallet.unlock_wallet(wallet_password)
    print(f"Wallet unlocked: {wallet.unlocked}")
    
    # Generate addresses
    receiving_addr = wallet.generate_address("main_receiving")
    savings_addr = wallet.generate_address("savings")
    
    print(f"Receiving address: {receiving_addr}")
    print(f"Savings address: {savings_addr}")
    
    # Simulate receiving funds
    wallet.balances[receiving_addr] = 1.5  # 1.5 BTC
    
    # Create transaction
    try:
        tx = wallet.create_transaction(
            to_address="bc1qexternaladdress12345",
            amount=0.5,
            from_label="main_receiving"
        )
        
        print(f"\nTransaction created:")
        print(f"  From: {tx['from']}")
        print(f"  To: {tx['to']}")
        print(f"  Amount: {tx['amount']} BTC")
        print(f"  Signature: {tx['signature'][:32]}...")
        
    except Exception as e:
        print(f"Transaction failed: {e}")
    
    return wallet

crypto_wallet = crypto_wallet_example()
```

---

## Best Practices Summary

### Security Best Practices
1. **Always use secure random number generation** for keys and IVs
2. **Validate all inputs** before processing
3. **Use constant-time operations** to prevent timing attacks
4. **Clear sensitive data** from memory after use
5. **Implement proper error handling** without information leakage

### Performance Best Practices
1. **Choose appropriate algorithms** for your use case
2. **Use hardware acceleration** when available
3. **Implement streaming** for large data sets
4. **Cache encryption contexts** for repeated operations
5. **Monitor and benchmark** critical operations

### Integration Best Practices
1. **Use proper key management** - never hardcode keys
2. **Implement proper access controls** and audit logging
3. **Use envelope encryption** for large data sets
4. **Implement secure communication protocols**
5. **Regular security audits** and updates

For more examples and detailed explanations, see the complete [User Guide](user_guide.md) and [API Reference](api.md).