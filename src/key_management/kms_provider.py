"""
Key Management Service (KMS) and Hardware Security Module (HSM) Provider Abstraction

This module provides a unified interface for key management operations across
different KMS providers and HSMs with envelope encryption support.
"""

import os
import json
import base64
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import secrets


class KeyPurpose(Enum):
    """Key usage purposes for policy enforcement."""
    ENCRYPTION = "encryption"
    SIGNING = "signing" 
    KEY_WRAPPING = "key_wrapping"
    KEY_EXCHANGE = "key_exchange"


class KeyType(Enum):
    """Types of cryptographic keys."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC_PRIVATE = "asymmetric_private"
    ASYMMETRIC_PUBLIC = "asymmetric_public"
    KEK = "key_encryption_key"
    DEK = "data_encryption_key"


@dataclass
class KeyMetadata:
    """Metadata for managed keys."""
    key_id: str
    key_type: KeyType
    purpose: KeyPurpose
    algorithm: str
    key_size: int
    created_at: float
    expires_at: Optional[float] = None
    owner: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    usage_count: int = 0
    last_used: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            'key_id': self.key_id,
            'key_type': self.key_type.value,
            'purpose': self.purpose.value,
            'algorithm': self.algorithm,
            'key_size': self.key_size,
            'created_at': self.created_at,
            'expires_at': self.expires_at,
            'owner': self.owner,
            'description': self.description,
            'tags': self.tags or {},
            'usage_count': self.usage_count,
            'last_used': self.last_used
        }
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyMetadata':
        """Create from dictionary."""
        return cls(
            key_id=data['key_id'],
            key_type=KeyType(data['key_type']),
            purpose=KeyPurpose(data['purpose']),
            algorithm=data['algorithm'],
            key_size=data['key_size'],
            created_at=data['created_at'],
            expires_at=data.get('expires_at'),
            owner=data.get('owner'),
            description=data.get('description'),
            tags=data.get('tags', {}),
            usage_count=data.get('usage_count', 0),
            last_used=data.get('last_used')
        )


@dataclass
class WrappedKey:
    """Container for envelope-encrypted key material."""
    key_id: str
    wrapped_key: bytes  # Encrypted with KEK
    kek_id: str        # Key encryption key identifier
    algorithm: str     # Wrapping algorithm
    metadata: KeyMetadata
    wrapped_at: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'key_id': self.key_id,
            'wrapped_key': base64.b64encode(self.wrapped_key).decode(),
            'kek_id': self.kek_id,
            'algorithm': self.algorithm,
            'metadata': self.metadata.to_dict(),
            'wrapped_at': self.wrapped_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WrappedKey':
        """Create from dictionary."""
        return cls(
            key_id=data['key_id'],
            wrapped_key=base64.b64decode(data['wrapped_key']),
            kek_id=data['kek_id'],
            algorithm=data['algorithm'],
            metadata=KeyMetadata.from_dict(data['metadata']),
            wrapped_at=data['wrapped_at']
        )


class KMSProvider(ABC):
    """Abstract base class for KMS providers."""
    
    @abstractmethod
    def generate_key(self, key_spec: str, key_usage: KeyPurpose, 
                    metadata: Optional[Dict[str, Any]] = None) -> str:
        """Generate a new key and return its ID."""
        pass
    
    @abstractmethod
    def encrypt(self, key_id: str, plaintext: bytes, 
               context: Optional[Dict[str, str]] = None) -> bytes:
        """Encrypt data using the specified key."""
        pass
    
    @abstractmethod
    def decrypt(self, key_id: str, ciphertext: bytes,
               context: Optional[Dict[str, str]] = None) -> bytes:
        """Decrypt data using the specified key."""
        pass
    
    @abstractmethod
    def wrap_key(self, kek_id: str, key_material: bytes) -> bytes:
        """Wrap (encrypt) key material using a key encryption key."""
        pass
    
    @abstractmethod
    def unwrap_key(self, kek_id: str, wrapped_key: bytes) -> bytes:
        """Unwrap (decrypt) key material using a key encryption key."""
        pass
    
    @abstractmethod
    def rotate_key(self, key_id: str) -> str:
        """Rotate a key and return the new key ID."""
        pass
    
    @abstractmethod
    def delete_key(self, key_id: str, schedule_days: int = 7) -> bool:
        """Schedule key deletion."""
        pass
    
    @abstractmethod
    def get_key_metadata(self, key_id: str) -> Dict[str, Any]:
        """Get metadata for a key."""
        pass


class LocalDevKMSProvider(KMSProvider):
    """
    Local development KMS provider.
    WARNING: Only use for development, not production!
    """
    
    def __init__(self, storage_path: str = "./dev_kms_keys.json"):
        self.storage_path = storage_path
        self.keys: Dict[str, Dict[str, Any]] = self._load_keys()
        
        # Generate master KEK if not exists
        if 'master_kek' not in self.keys:
            master_key = secrets.token_bytes(32)  # 256-bit AES key
            self.keys['master_kek'] = {
                'key_material': base64.b64encode(master_key).decode(),
                'created_at': time.time(),
                'algorithm': 'AES-256-GCM',
                'purpose': 'key_wrapping'
            }
            self._save_keys()
    
    def _load_keys(self) -> Dict[str, Dict[str, Any]]:
        """Load keys from local storage."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_keys(self):
        """Save keys to local storage."""
        os.makedirs(os.path.dirname(self.storage_path) if os.path.dirname(self.storage_path) else '.', exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(self.keys, f, indent=2)
    
    def generate_key(self, key_spec: str, key_usage: KeyPurpose,
                    metadata: Optional[Dict[str, Any]] = None) -> str:
        """Generate a new symmetric key."""
        key_id = f"dev-key-{secrets.token_hex(16)}"
        
        # Generate key material based on specification
        if key_spec == "AES-256":
            key_material = secrets.token_bytes(32)
        elif key_spec == "AES-128":
            key_material = secrets.token_bytes(16)
        elif key_spec == "ChaCha20":
            key_material = secrets.token_bytes(32)
        else:
            raise ValueError(f"Unsupported key spec: {key_spec}")
        
        self.keys[key_id] = {
            'key_material': base64.b64encode(key_material).decode(),
            'created_at': time.time(),
            'algorithm': key_spec,
            'purpose': key_usage.value,
            'metadata': metadata or {}
        }
        self._save_keys()
        
        return key_id
    
    def encrypt(self, key_id: str, plaintext: bytes,
               context: Optional[Dict[str, str]] = None) -> bytes:
        """Encrypt data using AES-GCM."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key_material = base64.b64decode(self.keys[key_id]['key_material'])
        
        # Create additional authenticated data from context
        aad = json.dumps(context or {}, sort_keys=True).encode() if context else b''
        
        # Encrypt with AES-GCM
        aead = AESGCM(key_material)
        nonce = os.urandom(12)
        ciphertext = aead.encrypt(nonce, plaintext, aad)
        
        return nonce + ciphertext
    
    def decrypt(self, key_id: str, ciphertext: bytes,
               context: Optional[Dict[str, str]] = None) -> bytes:
        """Decrypt data using AES-GCM."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key_material = base64.b64decode(self.keys[key_id]['key_material'])
        
        # Create additional authenticated data from context
        aad = json.dumps(context or {}, sort_keys=True).encode() if context else b''
        
        # Extract nonce and ciphertext
        nonce = ciphertext[:12]
        encrypted_data = ciphertext[12:]
        
        # Decrypt with AES-GCM
        aead = AESGCM(key_material)
        return aead.decrypt(nonce, encrypted_data, aad)
    
    def wrap_key(self, kek_id: str, key_material: bytes) -> bytes:
        """Wrap key material using AES-KW simulation."""
        if kek_id not in self.keys:
            raise ValueError(f"KEK not found: {kek_id}")
        
        kek_material = base64.b64decode(self.keys[kek_id]['key_material'])
        
        # Use AES-GCM for key wrapping (AES-KW would be better but this is dev-only)
        aead = AESGCM(kek_material)
        nonce = os.urandom(12)
        wrapped = aead.encrypt(nonce, key_material, b'key_wrapping')
        
        return nonce + wrapped
    
    def unwrap_key(self, kek_id: str, wrapped_key: bytes) -> bytes:
        """Unwrap key material using AES-KW simulation."""
        if kek_id not in self.keys:
            raise ValueError(f"KEK not found: {kek_id}")
        
        kek_material = base64.b64decode(self.keys[kek_id]['key_material'])
        
        # Extract nonce and wrapped data
        nonce = wrapped_key[:12]
        wrapped_data = wrapped_key[12:]
        
        # Unwrap using AES-GCM
        aead = AESGCM(kek_material)
        return aead.decrypt(nonce, wrapped_data, b'key_wrapping')
    
    def rotate_key(self, key_id: str) -> str:
        """Create a new version of the key."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        old_key = self.keys[key_id]
        new_key_id = f"{key_id}-rotated-{int(time.time())}"
        
        # Generate new key material with same algorithm
        algorithm = old_key['algorithm']
        if algorithm in ["AES-256", "ChaCha20"]:
            key_material = secrets.token_bytes(32)
        elif algorithm == "AES-128":
            key_material = secrets.token_bytes(16)
        else:
            raise ValueError(f"Cannot rotate key with algorithm: {algorithm}")
        
        self.keys[new_key_id] = {
            'key_material': base64.b64encode(key_material).decode(),
            'created_at': time.time(),
            'algorithm': algorithm,
            'purpose': old_key['purpose'],
            'metadata': old_key.get('metadata', {}),
            'previous_version': key_id
        }
        
        # Mark old key as rotated
        self.keys[key_id]['rotated_to'] = new_key_id
        self.keys[key_id]['status'] = 'rotated'
        
        self._save_keys()
        return new_key_id
    
    def delete_key(self, key_id: str, schedule_days: int = 7) -> bool:
        """Schedule key deletion."""
        if key_id not in self.keys:
            return False
        
        self.keys[key_id]['deletion_scheduled'] = time.time() + (schedule_days * 24 * 3600)
        self.keys[key_id]['status'] = 'scheduled_for_deletion'
        self._save_keys()
        return True
    
    def get_key_metadata(self, key_id: str) -> Dict[str, Any]:
        """Get key metadata."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key_data = self.keys[key_id].copy()
        # Remove sensitive key material
        key_data.pop('key_material', None)
        return key_data


class EnvelopeKeyManager:
    """
    Key manager implementing envelope encryption with KMS/HSM providers.
    
    This class implements the hierarchical key structure:
    Root Key (KMS/HSM) -> Key Encryption Key (KEK) -> Data Encryption Key (DEK)
    """
    
    def __init__(self, kms_provider: KMSProvider, storage_path: str = "./envelope_keys.json"):
        self.kms = kms_provider
        self.storage_path = storage_path
        self.wrapped_keys: Dict[str, WrappedKey] = self._load_wrapped_keys()
        
        # Initialize master KEK if not exists
        self.master_kek_id = self._ensure_master_kek()
    
    def _load_wrapped_keys(self) -> Dict[str, WrappedKey]:
        """Load wrapped keys from storage."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    return {k: WrappedKey.from_dict(v) for k, v in data.items()}
            except:
                return {}
        return {}
    
    def _save_wrapped_keys(self):
        """Save wrapped keys to storage."""
        os.makedirs(os.path.dirname(self.storage_path) if os.path.dirname(self.storage_path) else '.', exist_ok=True)
        data = {k: v.to_dict() for k, v in self.wrapped_keys.items()}
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _ensure_master_kek(self) -> str:
        """Ensure master Key Encryption Key exists."""
        # Look for existing master KEK
        for key_id, wrapped_key in self.wrapped_keys.items():
            if (wrapped_key.metadata.purpose == KeyPurpose.KEY_WRAPPING and
                wrapped_key.metadata.description == "Master KEK"):
                return key_id
        
        # Generate new master KEK
        kek_id = self.kms.generate_key(
            "AES-256", 
            KeyPurpose.KEY_WRAPPING,
            {"description": "Master Key Encryption Key", "role": "master_kek"}
        )
        
        return kek_id
    
    def generate_dek(self, algorithm: str = "AES-256", purpose: KeyPurpose = KeyPurpose.ENCRYPTION,
                    metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate a new Data Encryption Key (DEK) and wrap it with envelope encryption.
        
        Args:
            algorithm: Key algorithm specification
            purpose: Key usage purpose
            metadata: Additional key metadata
            
        Returns:
            Key ID for the wrapped DEK
        """
        # Generate key material locally
        if algorithm == "AES-256":
            key_material = secrets.token_bytes(32)
            key_size = 256
        elif algorithm == "AES-128":
            key_material = secrets.token_bytes(16)
            key_size = 128
        elif algorithm == "ChaCha20":
            key_material = secrets.token_bytes(32)
            key_size = 256
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Create key metadata
        key_id = f"dek-{secrets.token_hex(16)}"
        key_metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.DEK,
            purpose=purpose,
            algorithm=algorithm,
            key_size=key_size,
            created_at=time.time(),
            description=metadata.get('description') if metadata else None,
            owner=metadata.get('owner') if metadata else None,
            tags=metadata.get('tags') if metadata else None
        )
        
        # Wrap the key material using KMS
        wrapped_material = self.kms.wrap_key(self.master_kek_id, key_material)
        
        # Create wrapped key container
        wrapped_key = WrappedKey(
            key_id=key_id,
            wrapped_key=wrapped_material,
            kek_id=self.master_kek_id,
            algorithm="AES-256-GCM",  # Wrapping algorithm
            metadata=key_metadata,
            wrapped_at=time.time()
        )
        
        # Store wrapped key
        self.wrapped_keys[key_id] = wrapped_key
        self._save_wrapped_keys()
        
        # Clear sensitive key material from memory
        key_material = b'\x00' * len(key_material)
        
        return key_id
    
    def get_dek(self, key_id: str) -> bytes:
        """
        Unwrap and return a Data Encryption Key.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Unwrapped key material
        """
        if key_id not in self.wrapped_keys:
            raise ValueError(f"Key not found: {key_id}")
        
        wrapped_key = self.wrapped_keys[key_id]
        
        # Check if key is expired
        if (wrapped_key.metadata.expires_at and 
            time.time() > wrapped_key.metadata.expires_at):
            raise ValueError(f"Key expired: {key_id}")
        
        # Unwrap key material using KMS
        key_material = self.kms.unwrap_key(wrapped_key.kek_id, wrapped_key.wrapped_key)
        
        # Update usage statistics
        wrapped_key.metadata.usage_count += 1
        wrapped_key.metadata.last_used = time.time()
        self._save_wrapped_keys()
        
        return key_material
    
    def rotate_dek(self, key_id: str) -> str:
        """
        Rotate a Data Encryption Key by creating a new version.
        
        Args:
            key_id: Key to rotate
            
        Returns:
            New key ID
        """
        if key_id not in self.wrapped_keys:
            raise ValueError(f"Key not found: {key_id}")
        
        old_wrapped_key = self.wrapped_keys[key_id]
        old_metadata = old_wrapped_key.metadata
        
        # Generate new key with same specifications
        new_key_id = self.generate_dek(
            algorithm=old_metadata.algorithm,
            purpose=old_metadata.purpose,
            metadata={
                'description': old_metadata.description,
                'owner': old_metadata.owner,
                'tags': old_metadata.tags or {},
                'previous_version': key_id
            }
        )
        
        # Mark old key as rotated
        old_metadata.tags = old_metadata.tags or {}
        old_metadata.tags['status'] = 'rotated'
        old_metadata.tags['rotated_to'] = new_key_id
        self._save_wrapped_keys()
        
        return new_key_id
    
    def rewrap_keys(self, old_kek_id: str, new_kek_id: str) -> List[str]:
        """
        Rewrap all keys from old KEK to new KEK.
        
        Args:
            old_kek_id: Old Key Encryption Key ID
            new_kek_id: New Key Encryption Key ID
            
        Returns:
            List of rewrapped key IDs
        """
        rewrapped_keys = []
        
        for key_id, wrapped_key in self.wrapped_keys.items():
            if wrapped_key.kek_id == old_kek_id:
                # Unwrap with old KEK
                key_material = self.kms.unwrap_key(old_kek_id, wrapped_key.wrapped_key)
                
                # Rewrap with new KEK
                new_wrapped_material = self.kms.wrap_key(new_kek_id, key_material)
                
                # Update wrapped key
                wrapped_key.wrapped_key = new_wrapped_material
                wrapped_key.kek_id = new_kek_id
                wrapped_key.wrapped_at = time.time()
                
                # Clear sensitive material
                key_material = b'\x00' * len(key_material)
                
                rewrapped_keys.append(key_id)
        
        self._save_wrapped_keys()
        return rewrapped_keys
    
    def delete_key(self, key_id: str, secure_delete: bool = True) -> bool:
        """
        Delete a key from the envelope storage.
        
        Args:
            key_id: Key to delete
            secure_delete: Whether to perform secure deletion
            
        Returns:
            True if deleted successfully
        """
        if key_id not in self.wrapped_keys:
            return False
        
        if secure_delete:
            # Overwrite wrapped key data before deletion
            wrapped_key = self.wrapped_keys[key_id]
            wrapped_key.wrapped_key = b'\x00' * len(wrapped_key.wrapped_key)
        
        del self.wrapped_keys[key_id]
        self._save_wrapped_keys()
        return True
    
    def list_keys(self, include_metadata: bool = True) -> List[Dict[str, Any]]:
        """List all managed keys with optional metadata."""
        result = []
        for key_id, wrapped_key in self.wrapped_keys.items():
            key_info = {
                'key_id': key_id,
                'algorithm': wrapped_key.metadata.algorithm,
                'purpose': wrapped_key.metadata.purpose.value,
                'created_at': wrapped_key.metadata.created_at,
                'last_used': wrapped_key.metadata.last_used,
                'usage_count': wrapped_key.metadata.usage_count
            }
            
            if include_metadata:
                key_info['metadata'] = wrapped_key.metadata.to_dict()
            
            result.append(key_info)
        
        return sorted(result, key=lambda x: x['created_at'], reverse=True)
    
    def get_key_metadata(self, key_id: str) -> KeyMetadata:
        """Get metadata for a specific key."""
        if key_id not in self.wrapped_keys:
            raise ValueError(f"Key not found: {key_id}")
        
        return self.wrapped_keys[key_id].metadata