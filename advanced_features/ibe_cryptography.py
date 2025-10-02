"""
Identity-Based Encryption (IBE) Module

This module provides Identity-Based Encryption capabilities, allowing encryption
to an identity (like email address) without prior key exchange.

Note: This is a simplified implementation for demonstration purposes.
Production use would require a more robust pairing-based cryptography library.
"""

import hashlib
import os
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import time


class IBEMasterKey:
    """Master key for IBE system."""
    
    def __init__(self, master_secret: bytes, system_params: Dict[str, Any]):
        self.master_secret = master_secret
        self.system_params = system_params
        self.created_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize master key to dictionary."""
        return {
            'master_secret': self.master_secret.hex(),
            'system_params': self.system_params,
            'created_at': self.created_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IBEMasterKey':
        """Deserialize master key from dictionary."""
        return cls(
            master_secret=bytes.fromhex(data['master_secret']),
            system_params=data['system_params']
        )


class IBEPrivateKey:
    """Private key for a specific identity in IBE system."""
    
    def __init__(self, identity: str, private_key_data: bytes, 
                 system_params: Dict[str, Any]):
        self.identity = identity
        self.private_key_data = private_key_data
        self.system_params = system_params
        self.created_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize private key to dictionary."""
        return {
            'identity': self.identity,
            'private_key_data': self.private_key_data.hex(),
            'system_params': self.system_params,
            'created_at': self.created_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IBEPrivateKey':
        """Deserialize private key from dictionary."""
        return cls(
            identity=data['identity'],
            private_key_data=bytes.fromhex(data['private_key_data']),
            system_params=data['system_params']
        )


class SimplifiedIBE:
    """
    Simplified Identity-Based Encryption implementation.
    
    Note: This is a demonstration implementation using hash-based key derivation
    and traditional cryptographic primitives. A production IBE system would use
    pairing-based cryptography with proper mathematical foundations.
    """
    
    def __init__(self):
        self.security_parameter = 256  # bits
    
    def setup(self) -> Tuple[IBEMasterKey, Dict[str, Any]]:
        """
        Setup the IBE system and generate master keys.
        
        Returns:
            Tuple of (master_key, public_parameters)
        """
        # Generate master secret
        master_secret = os.urandom(self.security_parameter // 8)
        
        # Generate system parameters (simplified)
        system_params = {
            'security_parameter': self.security_parameter,
            'hash_algorithm': 'SHA256',
            'encryption_algorithm': 'AES-GCM',
            'system_id': os.urandom(16).hex()
        }
        
        master_key = IBEMasterKey(master_secret, system_params)
        
        return master_key, system_params
    
    def extract_private_key(self, master_key: IBEMasterKey, 
                           identity: str) -> IBEPrivateKey:
        """
        Extract a private key for a given identity.
        
        Args:
            master_key: The master key from setup
            identity: The identity (e.g., email address)
            
        Returns:
            Private key for the identity
        """
        # Hash the identity to create a deterministic input
        identity_hash = hashlib.sha256(identity.encode()).digest()
        
        # Derive private key using HKDF-like construction
        # In a real IBE system, this would use bilinear pairings
        private_key_material = hashlib.pbkdf2_hmac(
            'sha256',
            master_key.master_secret,
            identity_hash,
            100000,  # iterations
            32  # key length
        )
        
        return IBEPrivateKey(identity, private_key_material, master_key.system_params)
    
    def encrypt(self, system_params: Dict[str, Any], identity: str, 
                plaintext: bytes) -> Dict[str, Any]:
        """
        Encrypt data for a specific identity.
        
        Args:
            system_params: Public system parameters
            identity: Target identity
            plaintext: Data to encrypt
            
        Returns:
            Encrypted data structure
        """
        # Derive encryption key from identity (simplified approach)
        identity_hash = hashlib.sha256(identity.encode()).digest()
        
        # Generate a random session key
        session_key = os.urandom(32)
        
        # Encrypt the plaintext with the session key
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        # "Encrypt" the session key to the identity (simplified)
        # In real IBE, this would use the identity as a public key
        key_encryption_key = hashlib.pbkdf2_hmac(
            'sha256',
            identity_hash,
            system_params['system_id'].encode(),
            50000,
            32
        )
        
        # Encrypt session key
        key_iv = os.urandom(12)
        key_cipher = Cipher(algorithms.AES(key_encryption_key), modes.GCM(key_iv), 
                           backend=default_backend())
        key_encryptor = key_cipher.encryptor()
        encrypted_session_key = key_encryptor.update(session_key) + key_encryptor.finalize()
        key_tag = key_encryptor.tag
        
        return {
            'identity': identity,
            'encrypted_data': {
                'iv': iv.hex(),
                'ciphertext': ciphertext.hex(),
                'tag': tag.hex()
            },
            'encrypted_session_key': {
                'iv': key_iv.hex(),
                'ciphertext': encrypted_session_key.hex(),
                'tag': key_tag.hex()
            },
            'system_params': system_params
        }
    
    def decrypt(self, private_key: IBEPrivateKey, 
                encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data using an identity's private key.
        
        Args:
            private_key: Private key for the identity
            encrypted_data: Encrypted data structure
            
        Returns:
            Decrypted plaintext
        """
        # Verify identity matches
        if private_key.identity != encrypted_data['identity']:
            raise ValueError("Private key identity does not match encrypted data")
        
        # Derive the same key encryption key
        identity_hash = hashlib.sha256(private_key.identity.encode()).digest()
        key_encryption_key = hashlib.pbkdf2_hmac(
            'sha256',
            identity_hash,
            encrypted_data['system_params']['system_id'].encode(),
            50000,
            32
        )
        
        # Decrypt the session key
        key_data = encrypted_data['encrypted_session_key']
        key_iv = bytes.fromhex(key_data['iv'])
        key_ciphertext = bytes.fromhex(key_data['ciphertext'])
        key_tag = bytes.fromhex(key_data['tag'])
        
        key_cipher = Cipher(algorithms.AES(key_encryption_key), modes.GCM(key_iv, key_tag), 
                           backend=default_backend())
        key_decryptor = key_cipher.decryptor()
        session_key = key_decryptor.update(key_ciphertext) + key_decryptor.finalize()
        
        # Decrypt the actual data
        data = encrypted_data['encrypted_data']
        iv = bytes.fromhex(data['iv'])
        ciphertext = bytes.fromhex(data['ciphertext'])
        tag = bytes.fromhex(data['tag'])
        
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext


class IBEKeyManager:
    """Manager for IBE keys and operations."""
    
    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        self.ibe = SimplifiedIBE()
        self._ensure_storage_directory()
    
    def _ensure_storage_directory(self):
        """Ensure storage directory exists."""
        os.makedirs(self.storage_path, exist_ok=True)
    
    def initialize_system(self) -> Dict[str, Any]:
        """Initialize IBE system and store master key."""
        master_key, system_params = self.ibe.setup()
        
        # Store master key securely (in production, use HSM or secure enclave)
        master_key_file = os.path.join(self.storage_path, "master_key.json")
        with open(master_key_file, 'w') as f:
            json.dump(master_key.to_dict(), f, indent=2)
        
        # Store public parameters
        params_file = os.path.join(self.storage_path, "system_params.json")
        with open(params_file, 'w') as f:
            json.dump(system_params, f, indent=2)
        
        return system_params
    
    def load_system_params(self) -> Optional[Dict[str, Any]]:
        """Load system parameters."""
        params_file = os.path.join(self.storage_path, "system_params.json")
        if not os.path.exists(params_file):
            return None
        
        with open(params_file, 'r') as f:
            return json.load(f)
    
    def load_master_key(self) -> Optional[IBEMasterKey]:
        """Load master key."""
        master_key_file = os.path.join(self.storage_path, "master_key.json")
        if not os.path.exists(master_key_file):
            return None
        
        with open(master_key_file, 'r') as f:
            data = json.load(f)
            return IBEMasterKey.from_dict(data)
    
    def generate_private_key(self, identity: str) -> IBEPrivateKey:
        """Generate private key for an identity."""
        master_key = self.load_master_key()
        if not master_key:
            raise ValueError("IBE system not initialized")
        
        private_key = self.ibe.extract_private_key(master_key, identity)
        
        # Store private key
        key_file = os.path.join(self.storage_path, f"private_key_{hashlib.sha256(identity.encode()).hexdigest()[:16]}.json")
        with open(key_file, 'w') as f:
            json.dump(private_key.to_dict(), f, indent=2)
        
        return private_key
    
    def load_private_key(self, identity: str) -> Optional[IBEPrivateKey]:
        """Load private key for an identity."""
        key_file = os.path.join(self.storage_path, f"private_key_{hashlib.sha256(identity.encode()).hexdigest()[:16]}.json")
        if not os.path.exists(key_file):
            return None
        
        with open(key_file, 'r') as f:
            data = json.load(f)
            return IBEPrivateKey.from_dict(data)
    
    def encrypt_to_identity(self, identity: str, plaintext: bytes) -> Dict[str, Any]:
        """Encrypt data to a specific identity."""
        system_params = self.load_system_params()
        if not system_params:
            raise ValueError("IBE system not initialized")
        
        return self.ibe.encrypt(system_params, identity, plaintext)
    
    def decrypt_with_identity(self, identity: str, encrypted_data: Dict[str, Any]) -> bytes:
        """Decrypt data using identity's private key."""
        private_key = self.load_private_key(identity)
        if not private_key:
            # Try to generate private key if we have master key
            try:
                private_key = self.generate_private_key(identity)
            except ValueError:
                raise ValueError(f"No private key available for identity: {identity}")
        
        return self.ibe.decrypt(private_key, encrypted_data)

