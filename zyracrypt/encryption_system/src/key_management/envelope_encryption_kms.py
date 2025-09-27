"""
Enhanced Key Storage with Envelope Encryption and KMS/HSM Integration
Never stores final encryption keys in plaintext
Implements secure key wrapping and hierarchical key management
"""

import os
import json
import time
import hashlib
import struct
from typing import Dict, Optional, Tuple, Any, List
from dataclasses import dataclass, asdict
from enum import Enum

# Core cryptography
import nacl.secret
import nacl.utils
import nacl.encoding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend

# KMS integration (if available)
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False


class KeyStorageLevel(Enum):
    """Security levels for key storage"""
    STANDARD = "standard"          # Software-based encryption
    HSM_BACKED = "hsm_backed"     # Hardware Security Module
    FIPS_VALIDATED = "fips_validated"  # FIPS 140-2 Level 3
    QUANTUM_RESISTANT = "quantum_resistant"  # Post-quantum algorithms


@dataclass
class KeyMetadata:
    """Metadata for stored keys"""
    key_id: str
    algorithm: str
    key_size: int
    created_at: float
    purpose: str
    security_level: KeyStorageLevel
    version: int
    kms_key_id: Optional[str] = None
    hsm_backed: bool = False
    rotation_policy: Optional[Dict] = None


@dataclass
class WrappedKey:
    """Container for wrapped (encrypted) key material"""
    wrapped_key: bytes
    wrapping_algorithm: str
    metadata: KeyMetadata
    integrity_check: bytes
    envelope_version: str = "2.0"


class EnvelopeEncryptionManager:
    """
    Advanced envelope encryption with KMS/HSM integration
    Implements hierarchical key management with defense-in-depth
    """
    
    def __init__(self, kms_region: str = 'us-west-2', use_hsm: bool = False):
        """Initialize with KMS configuration"""
        self.backend = default_backend()
        self.use_hsm = use_hsm
        
        # Initialize KMS client if available
        if AWS_AVAILABLE:
            self.kms_client = boto3.client('kms', region_name=kms_region)
            self.kms_available = True
        else:
            self.kms_client = None
            self.kms_available = False
        
        # Initialize master key
        self.master_key_id = None
        self.local_master_key = None
        self._init_master_key()
        
        # Key cache for performance (with secure cleanup)
        self._key_cache: Dict[str, Tuple[bytes, float]] = {}
        self._cache_ttl = 300  # 5 minutes
    
    def _init_master_key(self):
        """Initialize master key (KMS or local)"""
        if self.kms_available:
            try:
                # Try to get existing master key or create new one
                self.master_key_id = self._get_or_create_master_key()
            except Exception as e:
                print(f"Warning: KMS not available, using local master key: {e}")
                self._create_local_master_key()
        else:
            self._create_local_master_key()
    
    def _get_or_create_master_key(self) -> str:
        """Get existing master key or create new one in KMS"""
        key_description = 'Advanced Encryption System Master Key'
        
        # Try to find existing key
        try:
            response = self.kms_client.list_keys(Limit=100)
            for key in response['Keys']:
                key_detail = self.kms_client.describe_key(KeyId=key['KeyId'])
                if key_detail['KeyMetadata'].get('Description') == key_description:
                    return key['KeyId']
        except ClientError:
            pass
        
        # Create new master key
        try:
            response = self.kms_client.create_key(
                Description=key_description,
                KeyUsage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS' if not self.use_hsm else 'AWS_CLOUDHSM'
            )
            
            # Enable key rotation
            self.kms_client.enable_key_rotation(KeyId=response['KeyMetadata']['KeyId'])
            
            return response['KeyMetadata']['KeyId']
        except ClientError as e:
            raise RuntimeError(f"Failed to create master key: {e}")
    
    def _create_local_master_key(self):
        """Create local master key for environments without KMS"""
        # This is a fallback - in production, always use KMS/HSM
        self.local_master_key = nacl.utils.random(32)  # 256-bit key
        
    def generate_data_encryption_key(self, 
                                   purpose: str,
                                   algorithm: str = "AES-256-GCM",
                                   security_level: KeyStorageLevel = KeyStorageLevel.STANDARD) -> Tuple[str, WrappedKey]:
        """
        Generate a new data encryption key (DEK) with envelope encryption
        Returns: (key_id, wrapped_key_material)
        """
        key_id = self._generate_key_id()
        
        # Generate the actual DEK
        if algorithm == "AES-256-GCM":
            dek = nacl.utils.random(32)  # 256-bit key
            key_size = 256
        elif algorithm == "ChaCha20-Poly1305":
            dek = nacl.utils.random(32)  # 256-bit key
            key_size = 256
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Create metadata
        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=algorithm,
            key_size=key_size,
            created_at=time.time(),
            purpose=purpose,
            security_level=security_level,
            version=1,
            kms_key_id=self.master_key_id,
            hsm_backed=self.use_hsm
        )
        
        # Wrap the DEK
        wrapped_key = self._wrap_key(dek, metadata)
        
        return key_id, wrapped_key
    
    def _wrap_key(self, key_material: bytes, metadata: KeyMetadata) -> WrappedKey:
        """
        Wrap (encrypt) key material using envelope encryption
        """
        if self.kms_available and self.master_key_id:
            # Use KMS for wrapping
            wrapped_dek = self._kms_wrap_key(key_material)
            wrapping_algorithm = "AWS-KMS"
        else:
            # Use local master key for wrapping
            wrapped_dek = self._local_wrap_key(key_material)
            wrapping_algorithm = "AES-256-GCM-Local"
        
        # Create integrity check
        metadata_dict = asdict(metadata)
        metadata_dict['security_level'] = metadata.security_level.value  # Convert enum to string
        metadata_json = json.dumps(metadata_dict, sort_keys=True).encode()
        integrity_data = wrapped_dek + metadata_json
        integrity_check = hashlib.sha256(integrity_data).digest()
        
        return WrappedKey(
            wrapped_key=wrapped_dek,
            wrapping_algorithm=wrapping_algorithm,
            metadata=metadata,
            integrity_check=integrity_check
        )
    
    def _kms_wrap_key(self, key_material: bytes) -> bytes:
        """Wrap key using AWS KMS"""
        try:
            response = self.kms_client.encrypt(
                KeyId=self.master_key_id,
                Plaintext=key_material
            )
            return response['CiphertextBlob']
        except ClientError as e:
            raise RuntimeError(f"KMS encryption failed: {e}")
    
    def _local_wrap_key(self, key_material: bytes) -> bytes:
        """Wrap key using local master key (fallback)"""
        if not self.local_master_key:
            raise RuntimeError("No local master key available")
        
        # Use NaCl SecretBox for wrapping
        box = nacl.secret.SecretBox(self.local_master_key)
        return box.encrypt(key_material)
    
    def unwrap_key(self, wrapped_key: WrappedKey) -> bytes:
        """
        Unwrap (decrypt) key material
        """
        # Verify integrity
        metadata_dict = asdict(wrapped_key.metadata)
        metadata_dict['security_level'] = wrapped_key.metadata.security_level.value  # Convert enum to string
        metadata_json = json.dumps(metadata_dict, sort_keys=True).encode()
        integrity_data = wrapped_key.wrapped_key + metadata_json
        expected_check = hashlib.sha256(integrity_data).digest()
        
        if not constant_time.bytes_eq(wrapped_key.integrity_check, expected_check):
            raise ValueError("Integrity check failed - key material may be corrupted")
        
        # Check cache first
        cache_key = wrapped_key.metadata.key_id
        if cache_key in self._key_cache:
            cached_key, timestamp = self._key_cache[cache_key]
            if time.time() - timestamp < self._cache_ttl:
                return cached_key
        
        # Unwrap based on wrapping algorithm
        if wrapped_key.wrapping_algorithm == "AWS-KMS":
            if not self.kms_available:
                raise RuntimeError("KMS not available for unwrapping")
            key_material = self._kms_unwrap_key(wrapped_key.wrapped_key)
        elif wrapped_key.wrapping_algorithm == "AES-256-GCM-Local":
            key_material = self._local_unwrap_key(wrapped_key.wrapped_key)
        else:
            raise ValueError(f"Unknown wrapping algorithm: {wrapped_key.wrapping_algorithm}")
        
        # Cache the unwrapped key
        self._key_cache[cache_key] = (key_material, time.time())
        
        return key_material
    
    def _kms_unwrap_key(self, wrapped_key: bytes) -> bytes:
        """Unwrap key using AWS KMS"""
        try:
            response = self.kms_client.decrypt(CiphertextBlob=wrapped_key)
            return response['Plaintext']
        except ClientError as e:
            raise RuntimeError(f"KMS decryption failed: {e}")
    
    def _local_unwrap_key(self, wrapped_key: bytes) -> bytes:
        """Unwrap key using local master key"""
        if not self.local_master_key:
            raise RuntimeError("No local master key available")
        
        box = nacl.secret.SecretBox(self.local_master_key)
        return box.decrypt(wrapped_key)
    
    def rotate_key(self, wrapped_key: WrappedKey, new_purpose: Optional[str] = None) -> Tuple[str, WrappedKey]:
        """
        Rotate a key to a new version
        """
        # Unwrap old key to get the material
        old_key_material = self.unwrap_key(wrapped_key)
        
        # Generate new key material
        new_key_material = nacl.utils.random(len(old_key_material))
        
        # Create new metadata with incremented version
        new_metadata = KeyMetadata(
            key_id=self._generate_key_id(),
            algorithm=wrapped_key.metadata.algorithm,
            key_size=wrapped_key.metadata.key_size,
            created_at=time.time(),
            purpose=new_purpose or wrapped_key.metadata.purpose,
            security_level=wrapped_key.metadata.security_level,
            version=wrapped_key.metadata.version + 1,
            kms_key_id=self.master_key_id,
            hsm_backed=self.use_hsm
        )
        
        # Wrap new key
        new_wrapped_key = self._wrap_key(new_key_material, new_metadata)
        
        # Clear old key from cache
        if wrapped_key.metadata.key_id in self._key_cache:
            del self._key_cache[wrapped_key.metadata.key_id]
        
        return new_metadata.key_id, new_wrapped_key
    
    def encrypt_with_wrapped_key(self, wrapped_key: WrappedKey, data: bytes) -> Dict[str, bytes]:
        """
        Encrypt data using a wrapped key
        """
        # Unwrap the key
        key_material = self.unwrap_key(wrapped_key)
        
        try:
            if wrapped_key.metadata.algorithm == "AES-256-GCM":
                return self._encrypt_aes_gcm(key_material, data)
            elif wrapped_key.metadata.algorithm == "ChaCha20-Poly1305":
                return self._encrypt_chacha20_poly1305(key_material, data)
            else:
                raise ValueError(f"Unsupported algorithm: {wrapped_key.metadata.algorithm}")
        finally:
            # Attempt to clear key from memory
            if isinstance(key_material, bytearray):
                for i in range(len(key_material)):
                    key_material[i] = 0
    
    def decrypt_with_wrapped_key(self, wrapped_key: WrappedKey, 
                                encrypted_data: Dict[str, bytes]) -> bytes:
        """
        Decrypt data using a wrapped key
        """
        # Unwrap the key
        key_material = self.unwrap_key(wrapped_key)
        
        try:
            if wrapped_key.metadata.algorithm == "AES-256-GCM":
                return self._decrypt_aes_gcm(key_material, encrypted_data)
            elif wrapped_key.metadata.algorithm == "ChaCha20-Poly1305":
                return self._decrypt_chacha20_poly1305(key_material, encrypted_data)
            else:
                raise ValueError(f"Unsupported algorithm: {wrapped_key.metadata.algorithm}")
        finally:
            # Attempt to clear key from memory
            if isinstance(key_material, bytearray):
                for i in range(len(key_material)):
                    key_material[i] = 0
    
    def _encrypt_aes_gcm(self, key: bytes, data: bytes) -> Dict[str, bytes]:
        """Encrypt using AES-256-GCM"""
        iv = nacl.utils.random(12)  # 96-bit IV for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return {
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag
        }
    
    def _decrypt_aes_gcm(self, key: bytes, encrypted_data: Dict[str, bytes]) -> bytes:
        """Decrypt using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key), 
            modes.GCM(encrypted_data['iv'], encrypted_data['tag']), 
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
    
    def _encrypt_chacha20_poly1305(self, key: bytes, data: bytes) -> Dict[str, bytes]:
        """Encrypt using ChaCha20-Poly1305"""
        box = nacl.secret.SecretBox(key)
        encrypted = box.encrypt(data)
        
        # Extract nonce and ciphertext from NaCl format
        nonce = encrypted[:nacl.secret.SecretBox.NONCE_SIZE]
        ciphertext = encrypted[nacl.secret.SecretBox.NONCE_SIZE:]
        
        return {
            'nonce': nonce,
            'ciphertext': ciphertext
        }
    
    def _decrypt_chacha20_poly1305(self, key: bytes, encrypted_data: Dict[str, bytes]) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        box = nacl.secret.SecretBox(key)
        
        # Reconstruct NaCl format
        nacl_encrypted = encrypted_data['nonce'] + encrypted_data['ciphertext']
        
        return box.decrypt(nacl_encrypted)
    
    def _generate_key_id(self) -> str:
        """Generate unique key identifier"""
        timestamp = int(time.time() * 1000000)  # microseconds
        random_bytes = nacl.utils.random(8)
        combined = struct.pack('>Q', timestamp) + random_bytes
        return hashlib.sha256(combined).hexdigest()[:32]
    
    def export_wrapped_key(self, wrapped_key: WrappedKey) -> str:
        """
        Export wrapped key as JSON string for storage
        """
        export_data = {
            'wrapped_key': nacl.encoding.Base64Encoder.encode(wrapped_key.wrapped_key).decode(),
            'wrapping_algorithm': wrapped_key.wrapping_algorithm,
            'metadata': asdict(wrapped_key.metadata),
            'integrity_check': nacl.encoding.Base64Encoder.encode(wrapped_key.integrity_check).decode(),
            'envelope_version': wrapped_key.envelope_version
        }
        
        # Convert security level enum to string
        if hasattr(wrapped_key.metadata.security_level, 'value'):
            export_data['metadata']['security_level'] = wrapped_key.metadata.security_level.value
        else:
            export_data['metadata']['security_level'] = str(wrapped_key.metadata.security_level)
        
        return json.dumps(export_data, sort_keys=True)
    
    def import_wrapped_key(self, exported_key: str) -> WrappedKey:
        """
        Import wrapped key from JSON string
        """
        data = json.loads(exported_key)
        
        # Convert security level back to enum
        try:
            data['metadata']['security_level'] = KeyStorageLevel(data['metadata']['security_level'])
        except (ValueError, TypeError):
            # Handle string values or fallback
            if isinstance(data['metadata']['security_level'], str):
                for level in KeyStorageLevel:
                    if level.value == data['metadata']['security_level']:
                        data['metadata']['security_level'] = level
                        break
                else:
                    data['metadata']['security_level'] = KeyStorageLevel.STANDARD
        
        metadata = KeyMetadata(**data['metadata'])
        
        return WrappedKey(
            wrapped_key=nacl.encoding.Base64Encoder.decode(data['wrapped_key']),
            wrapping_algorithm=data['wrapping_algorithm'],
            metadata=metadata,
            integrity_check=nacl.encoding.Base64Encoder.decode(data['integrity_check']),
            envelope_version=data['envelope_version']
        )
    
    def cleanup_cache(self):
        """Clean up expired entries from key cache"""
        current_time = time.time()
        expired_keys = [
            key_id for key_id, (_, timestamp) in self._key_cache.items()
            if current_time - timestamp > self._cache_ttl
        ]
        
        for key_id in expired_keys:
            del self._key_cache[key_id]
    
    def get_key_info(self, wrapped_key: WrappedKey) -> Dict[str, Any]:
        """Get information about a wrapped key without unwrapping it"""
        return {
            'key_id': wrapped_key.metadata.key_id,
            'algorithm': wrapped_key.metadata.algorithm,
            'key_size': wrapped_key.metadata.key_size,
            'created_at': wrapped_key.metadata.created_at,
            'purpose': wrapped_key.metadata.purpose,
            'security_level': wrapped_key.metadata.security_level.value,
            'version': wrapped_key.metadata.version,
            'kms_backed': wrapped_key.metadata.kms_key_id is not None,
            'hsm_backed': wrapped_key.metadata.hsm_backed,
            'wrapping_algorithm': wrapped_key.wrapping_algorithm
        }


class SecureKeyStore:
    """
    Secure key storage interface with automatic cleanup
    """
    
    def __init__(self, storage_path: str = "secure_keystore"):
        """Initialize secure key store"""
        self.storage_path = storage_path
        self.envelope_manager = EnvelopeEncryptionManager()
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_path, exist_ok=True)
    
    def store_key(self, key_id: str, wrapped_key: WrappedKey):
        """Store a wrapped key securely"""
        key_file = os.path.join(self.storage_path, f"{key_id}.key")
        exported_key = self.envelope_manager.export_wrapped_key(wrapped_key)
        
        # Write with secure permissions
        with open(key_file, 'w') as f:
            f.write(exported_key)
        
        # Set restrictive file permissions (Unix-like systems)
        try:
            os.chmod(key_file, 0o600)  # Owner read/write only
        except:
            pass  # Windows doesn't support chmod
    
    def load_key(self, key_id: str) -> WrappedKey:
        """Load a wrapped key"""
        key_file = os.path.join(self.storage_path, f"{key_id}.key")
        
        if not os.path.exists(key_file):
            raise ValueError(f"Key {key_id} not found")
        
        with open(key_file, 'r') as f:
            exported_key = f.read()
        
        return self.envelope_manager.import_wrapped_key(exported_key)
    
    def delete_key(self, key_id: str):
        """Securely delete a key"""
        key_file = os.path.join(self.storage_path, f"{key_id}.key")
        
        if os.path.exists(key_file):
            # Attempt secure deletion by overwriting
            try:
                with open(key_file, 'r+b') as f:
                    length = f.seek(0, 2)  # Get file size
                    f.seek(0)
                    f.write(os.urandom(length))  # Overwrite with random data
                    f.flush()
                    os.fsync(f.fileno())
            except:
                pass
            
            # Remove the file
            os.remove(key_file)
    
    def list_keys(self) -> List[str]:
        """List all stored key IDs"""
        keys = []
        for filename in os.listdir(self.storage_path):
            if filename.endswith('.key'):
                keys.append(filename[:-4])  # Remove .key extension
        return keys