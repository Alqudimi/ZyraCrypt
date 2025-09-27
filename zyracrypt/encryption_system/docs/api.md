# API Reference

This document provides comprehensive API documentation for the Advanced Encryption System, including both the Python library interface and the REST API endpoints.

## Python Library API

### Core Cryptography Module

#### SymmetricEncryption

```python
from core_cryptography.symmetric_encryption import SymmetricEncryption
```

##### Class: `SymmetricEncryption`

Provides symmetric encryption operations using AES-GCM and ChaCha20-Poly1305.

**Methods:**

###### `encrypt_aes_gcm(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = None) -> Tuple[bytes, bytes]`

Encrypts data using AES-GCM authenticated encryption.

**Parameters:**
- `key` (bytes): 256-bit encryption key (32 bytes)
- `iv` (bytes): Initialization vector (12 bytes recommended)
- `plaintext` (bytes): Data to encrypt
- `aad` (bytes, optional): Additional authenticated data

**Returns:**
- `Tuple[bytes, bytes]`: (ciphertext, authentication_tag)

**Raises:**
- `ValueError`: If key or IV length is invalid
- `TypeError`: If inputs are not bytes

**Example:**
```python
import os
enc = SymmetricEncryption()
key = os.urandom(32)
iv = os.urandom(12)
plaintext = b"Confidential message"

ciphertext, tag = enc.encrypt_aes_gcm(key, iv, plaintext)
```

###### `decrypt_aes_gcm(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = None) -> bytes`

Decrypts and verifies AES-GCM encrypted data.

**Parameters:**
- `key` (bytes): 256-bit decryption key (32 bytes)
- `iv` (bytes): Initialization vector used for encryption
- `ciphertext` (bytes): Encrypted data
- `tag` (bytes): Authentication tag from encryption
- `aad` (bytes, optional): Additional authenticated data

**Returns:**
- `bytes`: Decrypted plaintext

**Raises:**
- `cryptography.exceptions.InvalidTag`: If authentication fails
- `ValueError`: If parameters are invalid

**Example:**
```python
plaintext = enc.decrypt_aes_gcm(key, iv, ciphertext, tag)
```

###### `encrypt_chacha20_poly1305(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = None) -> Tuple[bytes, bytes]`

Encrypts data using ChaCha20-Poly1305 authenticated encryption.

**Parameters:**
- `key` (bytes): 256-bit encryption key (32 bytes)
- `nonce` (bytes): 96-bit nonce (12 bytes)
- `plaintext` (bytes): Data to encrypt
- `aad` (bytes, optional): Additional authenticated data

**Returns:**
- `Tuple[bytes, bytes]`: (ciphertext, authentication_tag)

#### AsymmetricEncryption

```python
from core_cryptography.asymmetric_encryption import AsymmetricEncryption
```

##### Class: `AsymmetricEncryption`

Provides asymmetric encryption and digital signature operations.

**Methods:**

###### `generate_rsa_key_pair(key_size: int = 2048) -> Tuple[bytes, bytes]`

Generates RSA key pair for encryption and signing.

**Parameters:**
- `key_size` (int): Key size in bits (2048, 3072, or 4096)

**Returns:**
- `Tuple[bytes, bytes]`: (private_key_pem, public_key_pem)

**Example:**
```python
asym = AsymmetricEncryption()
private_key, public_key = asym.generate_rsa_key_pair(2048)
```

###### `rsa_encrypt(public_key_pem: bytes, plaintext: bytes) -> bytes`

Encrypts data using RSA-OAEP.

**Parameters:**
- `public_key_pem` (bytes): RSA public key in PEM format
- `plaintext` (bytes): Data to encrypt (max 190 bytes for 2048-bit key)

**Returns:**
- `bytes`: Encrypted ciphertext

###### `rsa_decrypt(private_key_pem: bytes, ciphertext: bytes) -> bytes`

Decrypts RSA-OAEP encrypted data.

**Parameters:**
- `private_key_pem` (bytes): RSA private key in PEM format
- `ciphertext` (bytes): Encrypted data

**Returns:**
- `bytes`: Decrypted plaintext

#### EncryptionFramework

```python
from core_cryptography.encryption_framework import EncryptionFramework
```

##### Class: `EncryptionFramework`

High-level encryption interface with automatic algorithm selection.

**Methods:**

###### `encrypt(plaintext: bytes, key: bytes, encryption_type: str = "auto") -> Tuple[str, bytes, bytes, bytes]`

Encrypts data with automatic or specified algorithm selection.

**Parameters:**
- `plaintext` (bytes): Data to encrypt
- `key` (bytes): Encryption key
- `encryption_type` (str): Algorithm ("auto", "AES-GCM", "ChaCha20-Poly1305")

**Returns:**
- `Tuple[str, bytes, bytes, bytes]`: (algorithm_name, iv, ciphertext, tag)

**Example:**
```python
framework = EncryptionFramework()
key = os.urandom(32)
plaintext = b"Secret data"

algorithm, iv, ciphertext, tag = framework.encrypt(plaintext, key)
```

### Key Management Module

#### KeyManager

```python
from key_management.key_manager import KeyManager
```

##### Class: `KeyManager`

Comprehensive key management with secure storage and lifecycle operations.

**Methods:**

###### `__init__(key_store_path: str = None, master_key: bytes = None)`

Initialize KeyManager with optional custom storage path.

**Parameters:**
- `key_store_path` (str, optional): Path to key storage file
- `master_key` (bytes, optional): Master key for encryption

###### `generate_symmetric_key(key_size: int = 256) -> bytes`

Generates cryptographically secure symmetric key.

**Parameters:**
- `key_size` (int): Key size in bits (128, 192, or 256)

**Returns:**
- `bytes`: Generated symmetric key

###### `generate_and_store_symmetric_key(key_id: str, key_size: int = 256) -> bytes`

Generates and securely stores a symmetric key.

**Parameters:**
- `key_id` (str): Unique identifier for the key
- `key_size` (int): Key size in bits

**Returns:**
- `bytes`: Generated key

**Example:**
```python
key_manager = KeyManager()
key = key_manager.generate_and_store_symmetric_key("my_app_key", 256)
```

###### `retrieve_key(key_id: str) -> bytes`

Retrieves a stored key by its identifier.

**Parameters:**
- `key_id` (str): Key identifier

**Returns:**
- `bytes`: Retrieved key

**Raises:**
- `KeyError`: If key_id not found

### Advanced Features

#### EnhancedKDF

```python
from key_management.enhanced_kdf_password import EnhancedKDF, KDFAlgorithm
```

##### Class: `EnhancedKDF`

Advanced key derivation with modern algorithms.

**Methods:**

###### `derive_key(password: bytes, salt: bytes, algorithm: KDFAlgorithm, key_length: int = 32) -> KDFResult`

Derives key from password using specified algorithm.

**Parameters:**
- `password` (bytes): Input password
- `salt` (bytes): Cryptographic salt
- `algorithm` (KDFAlgorithm): Algorithm (ARGON2ID, ARGON2I, SCRYPT, PBKDF2_SHA256)
- `key_length` (int): Desired key length in bytes

**Returns:**
- `KDFResult`: Object containing derived key and metadata

**Example:**
```python
kdf = EnhancedKDF()
result = kdf.derive_key(
    password=b"user_password",
    salt=os.urandom(32),
    algorithm=KDFAlgorithm.ARGON2ID,
    key_length=32
)
derived_key = result.key
```

#### HybridPQCEngine

```python
from advanced_features.hybrid_pqc_enhanced import HybridPQCEngine
```

##### Class: `HybridPQCEngine`

Hybrid post-quantum cryptography for quantum-resistant security.

**Methods:**

###### `generate_hybrid_keypair() -> Tuple[Dict[str, bytes], Dict[str, bytes]]`

Generates hybrid classical/post-quantum key pair.

**Returns:**
- `Tuple[Dict[str, bytes], Dict[str, bytes]]`: (public_keys, private_keys)

**Example:**
```python
pqc = HybridPQCEngine()
public_keys, private_keys = pqc.generate_hybrid_keypair()
```

## REST API Endpoints

The Flask web service provides REST API access to encryption functionality.

### Base URL

```
http://localhost:5000
```

### Authentication

Currently, the API operates in development mode without authentication. For production deployment, implement proper authentication mechanisms.

### Common Headers

```
Content-Type: application/json
Accept: application/json
```

### Endpoints

#### GET /api/health

Returns system health and loaded modules status.

**Response:**
```json
{
  "status": "healthy",
  "service": "Advanced Encryption System",
  "version": "2.0.0 - Enterprise Edition",
  "loaded_modules": ["symmetric", "asymmetric", "framework", ...],
  "features": {
    "core_encryption": true,
    "enhanced_kdf": true,
    "envelope_encryption": true,
    "side_channel_protection": true,
    "threshold_multisig": true,
    "hybrid_pqc": true,
    "algorithm_agility": true,
    "secure_mpc": true
  }
}
```

#### POST /api/encrypt

Encrypts text data using automatic algorithm selection.

**Request:**
```json
{
  "text": "Hello, World!",
  "algorithm": "auto"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "algorithm_used": "AES-GCM (auto-selected)",
    "encrypted_data": "base64_encoded_ciphertext",
    "iv": "base64_encoded_iv",
    "tag": "base64_encoded_tag",
    "key_id": "demo_key_abcd1234",
    "note": "In production, keys should be managed securely and never returned in API responses"
  }
}
```

**Security Note**: This demo endpoint generates and uses temporary keys for demonstration purposes. Production deployments should implement proper key management where keys are never exposed in API responses.

#### POST /api/decrypt

Decrypts previously encrypted data.

**Request:**
```json
{
  "encrypted_data": "base64_encoded_ciphertext",
  "iv": "base64_encoded_iv",
  "tag": "base64_encoded_tag",
  "key": "base64_encoded_key"
}
```

**Response:**
```json
{
  "success": true,
  "decrypted_text": "Hello, World!"
}
```

#### POST /api/enhanced-kdf

Derives keys using modern key derivation functions.

**Request:**
```json
{
  "password": "user_password",
  "algorithm": "argon2id",
  "salt_length": 32,
  "key_length": 32
}
```

**Response:**
```json
{
  "success": true,
  "algorithm": "argon2id",
  "derived_key": "base64_encoded_key",
  "salt": "base64_encoded_salt",
  "key_length": 32,
  "security_level": "enterprise"
}
```

#### POST /api/envelope-encryption

Performs envelope encryption with key wrapping.

**Request:**
```json
{
  "text": "Sensitive data",
  "key_id": "optional_key_identifier"
}
```

**Response:**
```json
{
  "success": true,
  "key_id": "generated_key_id",
  "wrapped_key": "base64_encoded_wrapped_key",
  "encrypted_data": "base64_encoded_ciphertext",
  "iv": "base64_encoded_iv",
  "tag": "base64_encoded_tag",
  "security_features": [
    "envelope_encryption",
    "never_stores_plaintext_keys",
    "kms_integration",
    "key_rotation_support"
  ]
}
```

#### POST /api/side-channel-safe

Demonstrates side-channel resistant operations.

**Request:**
```json
{
  "value1": "test_value_1",
  "value2": "test_value_2"
}
```

**Response:**
```json
{
  "success": true,
  "constant_time_equal": false,
  "timing_safe_hmac": "base64_encoded_hmac",
  "protections": [
    "constant_time_operations",
    "timing_attack_resistance",
    "secure_memory_handling",
    "cache_attack_mitigation"
  ]
}
```

#### POST /api/threshold-multisig

Creates threshold signatures with m-of-n multisig.

**Request:**
```json
{
  "message": "Document to sign",
  "threshold": 2,
  "total_signers": 3
}
```

**Response:**
```json
{
  "success": true,
  "policy_id": "demo-policy-abcd1234",
  "threshold": 2,
  "total_signers": 3,
  "signature": "base64_encoded_signature",
  "partial_signatures_used": 2,
  "features": [
    "distributed_key_responsibility",
    "shamir_secret_sharing",
    "threshold_cryptography",
    "m_of_n_signatures"
  ]
}
```

#### POST /api/hybrid-pqc

Demonstrates hybrid post-quantum cryptography key exchange.

**Request:**
```json
{
  "security_level": 128,
  "message": "Hello PQC World!"
}
```

**Response:**
```json
{
  "success": true,
  "security_level": 128,
  "library_used": "liboqs-python",
  "secrets_match": true,
  "key_exchange_successful": true,
  "algorithm_info": {
    "classical": "ECDH-P256",
    "post_quantum": "Kyber512"
  },
  "features": [
    "hybrid_classical_pq_key_exchange",
    "ml_kem_integration",
    "quantum_resistant_cryptography",
    "defense_in_depth_security"
  ]
}
```

### Error Responses

All endpoints return error responses in the following format:

```json
{
  "error": "Error description",
  "success": false
}
```

Common HTTP status codes:
- `200 OK`: Successful operation
- `400 Bad Request`: Invalid input parameters
- `500 Internal Server Error`: Server-side error

### Rate Limiting

Currently no rate limiting is implemented. For production deployment, implement appropriate rate limiting based on your security requirements.

### Security Considerations

1. **HTTPS**: Always use HTTPS in production environments
2. **Authentication**: Implement proper authentication for API access
3. **Input Validation**: All inputs are validated, but additional application-level validation is recommended
4. **Key Management**: Never expose actual keys in logs or error messages
5. **Audit Logging**: Implement audit logging for all cryptographic operations

### SDK Development

For language-specific SDKs, implement HTTP clients that interact with these REST endpoints. Ensure proper error handling and secure key transmission.

### WebSocket Support

For real-time applications requiring streaming encryption, consider implementing WebSocket endpoints for low-latency operations.

This API documentation follows OpenAPI/Swagger specifications and can be extended with formal API schema definitions for automated client generation.