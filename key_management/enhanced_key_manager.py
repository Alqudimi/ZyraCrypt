"""
Enhanced Key Management System

This module provides comprehensive key lifecycle management including generation,
storage, rotation, and revocation for various cryptographic algorithms.
"""

import os
import json
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets


class KeyMetadata:
    """Metadata for cryptographic keys."""
    
    def __init__(self, key_id: str, algorithm: str, purpose: str, 
                 created_at: float, expires_at: Optional[float] = None):
        self.key_id = key_id
        self.algorithm = algorithm
        self.purpose = purpose  # "encryption", "signing", "key_exchange"
        self.created_at = created_at
        self.expires_at = expires_at
        self.usage_count = 0
        self.last_used = None
        self.is_revoked = False
        self.revoked_at = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'purpose': self.purpose,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'usage_count': self.usage_count,
            'last_used': self.last_used,
            'is_revoked': self.is_revoked,
            'revoked_at': self.revoked_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyMetadata':
        """Create metadata from dictionary."""
        metadata = cls(
            data['key_id'],
            data['algorithm'],
            data['purpose'],
            data['created_at'],
            data.get('expires_at')
        )
        metadata.usage_count = data.get('usage_count', 0)
        metadata.last_used = data.get('last_used')
        metadata.is_revoked = data.get('is_revoked', False)
        metadata.revoked_at = data.get('revoked_at')
        return metadata


class SecureKeyStorage:
    """Secure storage for cryptographic keys."""
    
    def __init__(self, storage_path: str, master_password: str):
        self.storage_path = storage_path
        self.salt_file = os.path.join(storage_path, "master.salt")
        self.master_key = self._derive_master_key(master_password)
        self.metadata_file = os.path.join(storage_path, "key_metadata.json")
        self._ensure_storage_directory()
    
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create a new random salt per installation."""
        if os.path.exists(self.salt_file):
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            # Generate a new random salt for this installation
            salt = os.urandom(32)  # 256-bit salt
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
            return salt
    
    def _derive_master_key(self, password: str) -> bytes:
        """Derive master key from password using PBKDF2 with random salt."""
        salt = self._get_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Consider increasing to 480000+ for production
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _ensure_storage_directory(self):
        """Ensure storage directory exists."""
        os.makedirs(self.storage_path, exist_ok=True)
    
    def _encrypt_key_data(self, key_data: bytes) -> bytes:
        """Encrypt key data using master key."""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key_data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    
    def _decrypt_key_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt key data using master key."""
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def store_key(self, key_id: str, key_data: bytes, metadata: KeyMetadata):
        """Store a key with its metadata."""
        # Encrypt and store key data
        encrypted_key = self._encrypt_key_data(key_data)
        key_file = os.path.join(self.storage_path, f"{key_id}.key")
        with open(key_file, 'wb') as f:
            f.write(encrypted_key)
        
        # Update metadata
        self._update_metadata(metadata)
    
    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a key by its ID."""
        key_file = os.path.join(self.storage_path, f"{key_id}.key")
        if not os.path.exists(key_file):
            return None
        
        with open(key_file, 'rb') as f:
            encrypted_key = f.read()
        
        return self._decrypt_key_data(encrypted_key)
    
    def delete_key(self, key_id: str):
        """Securely delete a key."""
        key_file = os.path.join(self.storage_path, f"{key_id}.key")
        if os.path.exists(key_file):
            # Overwrite file with random data before deletion
            file_size = os.path.getsize(key_file)
            with open(key_file, 'wb') as f:
                f.write(os.urandom(file_size))
            os.remove(key_file)
    
    def _update_metadata(self, metadata: KeyMetadata):
        """Update key metadata."""
        all_metadata = self._load_all_metadata()
        all_metadata[metadata.key_id] = metadata.to_dict()
        
        with open(self.metadata_file, 'w') as f:
            json.dump(all_metadata, f, indent=2)
    
    def _load_all_metadata(self) -> Dict[str, Dict]:
        """Load all key metadata."""
        if not os.path.exists(self.metadata_file):
            return {}
        
        with open(self.metadata_file, 'r') as f:
            return json.load(f)
    
    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata for a specific key."""
        all_metadata = self._load_all_metadata()
        if key_id in all_metadata:
            return KeyMetadata.from_dict(all_metadata[key_id])
        return None
    
    def list_keys(self, purpose: Optional[str] = None, 
                  include_revoked: bool = False) -> List[KeyMetadata]:
        """List all keys with optional filtering."""
        all_metadata = self._load_all_metadata()
        keys = []
        
        for key_data in all_metadata.values():
            metadata = KeyMetadata.from_dict(key_data)
            
            # Filter by purpose if specified
            if purpose and metadata.purpose != purpose:
                continue
            
            # Filter revoked keys if not requested
            if not include_revoked and metadata.is_revoked:
                continue
            
            keys.append(metadata)
        
        return keys


class EnhancedKeyManager:
    """Enhanced key management system with lifecycle management."""
    
    def __init__(self, storage_path: str, master_password: str):
        self.storage = SecureKeyStorage(storage_path, master_password)
        self.key_derivation = KeyDerivationManager()
    
    def generate_key_id(self, algorithm: str, purpose: str) -> str:
        """Generate a unique key ID."""
        timestamp = str(int(time.time()))
        random_part = secrets.token_hex(8)
        return f"{algorithm}_{purpose}_{timestamp}_{random_part}"
    
    def create_key(self, algorithm: str, purpose: str, key_size: int = 256,
                   expires_in_days: Optional[int] = None) -> Tuple[str, bytes]:
        """Create a new cryptographic key."""
        key_id = self.generate_key_id(algorithm, purpose)
        
        # Generate key based on algorithm
        if algorithm.lower() in ['aes', 'chacha20']:
            key_data = os.urandom(key_size // 8)
        else:
            # For other algorithms, generate random key material
            key_data = os.urandom(key_size // 8)
        
        # Calculate expiration time
        expires_at = None
        if expires_in_days:
            expires_at = time.time() + (expires_in_days * 24 * 3600)
        
        # Create metadata
        metadata = KeyMetadata(
            key_id=key_id,
            algorithm=algorithm,
            purpose=purpose,
            created_at=time.time(),
            expires_at=expires_at
        )
        
        # Store key
        self.storage.store_key(key_id, key_data, metadata)
        
        return key_id, key_data
    
    def get_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a key and update usage statistics."""
        # Check if key exists and is valid
        metadata = self.storage.get_metadata(key_id)
        if not metadata:
            return None
        
        if metadata.is_revoked:
            raise ValueError(f"Key {key_id} has been revoked")
        
        if metadata.expires_at and time.time() > metadata.expires_at:
            raise ValueError(f"Key {key_id} has expired")
        
        # Update usage statistics
        metadata.usage_count += 1
        metadata.last_used = time.time()
        self.storage._update_metadata(metadata)
        
        return self.storage.retrieve_key(key_id)
    
    def revoke_key(self, key_id: str, reason: str = ""):
        """Revoke a key."""
        metadata = self.storage.get_metadata(key_id)
        if not metadata:
            raise ValueError(f"Key {key_id} not found")
        
        metadata.is_revoked = True
        metadata.revoked_at = time.time()
        self.storage._update_metadata(metadata)
    
    def rotate_key(self, old_key_id: str) -> Tuple[str, bytes]:
        """Rotate a key by creating a new one with the same properties."""
        old_metadata = self.storage.get_metadata(old_key_id)
        if not old_metadata:
            raise ValueError(f"Key {old_key_id} not found")
        
        # Create new key with same properties
        expires_in_days = None
        if old_metadata.expires_at:
            expires_in_days = int((old_metadata.expires_at - time.time()) / (24 * 3600))
            expires_in_days = max(expires_in_days, 1)  # At least 1 day
        
        new_key_id, new_key_data = self.create_key(
            algorithm=old_metadata.algorithm,
            purpose=old_metadata.purpose,
            expires_in_days=expires_in_days
        )
        
        # Revoke old key
        self.revoke_key(old_key_id, "Key rotated")
        
        return new_key_id, new_key_data
    
    def cleanup_expired_keys(self):
        """Remove expired keys from storage."""
        current_time = time.time()
        all_keys = self.storage.list_keys(include_revoked=True)
        
        for metadata in all_keys:
            if metadata.expires_at and current_time > metadata.expires_at:
                # Grace period of 7 days after expiration
                if current_time > (metadata.expires_at + 7 * 24 * 3600):
                    self.storage.delete_key(metadata.key_id)
    
    def get_key_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored keys."""
        all_keys = self.storage.list_keys(include_revoked=True)
        
        stats = {
            'total_keys': len(all_keys),
            'active_keys': len([k for k in all_keys if not k.is_revoked]),
            'revoked_keys': len([k for k in all_keys if k.is_revoked]),
            'expired_keys': len([k for k in all_keys if k.expires_at and time.time() > k.expires_at]),
            'algorithms': {},
            'purposes': {}
        }
        
        for key in all_keys:
            # Count by algorithm
            if key.algorithm not in stats['algorithms']:
                stats['algorithms'][key.algorithm] = 0
            stats['algorithms'][key.algorithm] += 1
            
            # Count by purpose
            if key.purpose not in stats['purposes']:
                stats['purposes'][key.purpose] = 0
            stats['purposes'][key.purpose] += 1
        
        return stats


class KeyDerivationManager:
    """Manager for key derivation functions."""
    
    @staticmethod
    def derive_key_hkdf(master_key: bytes, info: bytes, length: int = 32) -> bytes:
        """Derive a key using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(master_key)
    
    @staticmethod
    def derive_multiple_keys(master_key: bytes, purposes: List[str], 
                           length: int = 32) -> Dict[str, bytes]:
        """Derive multiple keys for different purposes."""
        derived_keys = {}
        for purpose in purposes:
            info = purpose.encode('utf-8')
            derived_keys[purpose] = KeyDerivationManager.derive_key_hkdf(
                master_key, info, length
            )
        return derived_keys

