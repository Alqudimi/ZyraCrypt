"""
Algorithm Agility and Versioning Protocol
Enables seamless algorithm upgrades and cryptographic migration
Implements forward compatibility and deprecation management
"""

import os
import json
import time
import hashlib
import struct
from typing import Dict, List, Optional, Tuple, Any, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum, IntEnum
from abc import ABC, abstractmethod

# Core cryptography
import nacl.secret
import nacl.utils
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AlgorithmType(Enum):
    """Types of cryptographic algorithms"""
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    ASYMMETRIC_ENCRYPTION = "asymmetric_encryption"
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_DERIVATION = "key_derivation"
    MESSAGE_AUTHENTICATION = "message_authentication"
    POST_QUANTUM_KEM = "post_quantum_kem"
    POST_QUANTUM_SIGNATURE = "post_quantum_signature"


class SecurityLevel(IntEnum):
    """Security levels in bits"""
    LEVEL_128 = 128
    LEVEL_192 = 192
    LEVEL_256 = 256


class AlgorithmStatus(Enum):
    """Algorithm lifecycle status"""
    APPROVED = "approved"           # Recommended for new systems
    ACCEPTABLE = "acceptable"       # Acceptable for existing systems
    DEPRECATED = "deprecated"       # Scheduled for removal
    PROHIBITED = "prohibited"       # Must not be used
    EXPERIMENTAL = "experimental"   # For testing only


@dataclass
class AlgorithmSpec:
    """Specification for a cryptographic algorithm"""
    algorithm_id: str
    name: str
    algorithm_type: AlgorithmType
    security_level: SecurityLevel
    status: AlgorithmStatus
    version: str
    implementation: str
    key_size: Optional[int] = None
    parameters: Optional[Dict[str, Any]] = None
    deprecation_date: Optional[float] = None
    replacement_algorithm: Optional[str] = None
    compliance_standards: Optional[List[str]] = None


@dataclass
class CryptographicContext:
    """Context for cryptographic operations"""
    version: str
    algorithm_spec: AlgorithmSpec
    operation_id: str
    timestamp: float
    metadata: Optional[Dict[str, Any]] = None


class AlgorithmRegistry:
    """
    Registry of supported cryptographic algorithms with versioning
    """
    
    def __init__(self):
        """Initialize algorithm registry"""
        self.algorithms: Dict[str, AlgorithmSpec] = {}
        self.algorithm_history: Dict[str, List[AlgorithmSpec]] = {}
        self.migration_rules: Dict[str, str] = {}
        
        # Initialize with default algorithms
        self._register_default_algorithms()
    
    def _register_default_algorithms(self):
        """Register default cryptographic algorithms"""
        
        # Symmetric encryption algorithms
        self.register_algorithm(AlgorithmSpec(
            algorithm_id="aes-256-gcm-v1",
            name="AES-256-GCM",
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_level=SecurityLevel.LEVEL_256,
            status=AlgorithmStatus.APPROVED,
            version="1.0",
            implementation="cryptography",
            key_size=256,
            compliance_standards=["FIPS-140-2", "Common Criteria"]
        ))
        
        self.register_algorithm(AlgorithmSpec(
            algorithm_id="chacha20-poly1305-v1",
            name="ChaCha20-Poly1305",
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_level=SecurityLevel.LEVEL_256,
            status=AlgorithmStatus.APPROVED,
            version="1.0",
            implementation="nacl",
            key_size=256
        ))
        
        # Post-quantum algorithms
        self.register_algorithm(AlgorithmSpec(
            algorithm_id="ml-kem-768-v1",
            name="ML-KEM-768",
            algorithm_type=AlgorithmType.POST_QUANTUM_KEM,
            security_level=SecurityLevel.LEVEL_192,
            status=AlgorithmStatus.APPROVED,
            version="1.0",
            implementation="quantcrypt",
            compliance_standards=["NIST-FIPS-203"]
        ))
        
        self.register_algorithm(AlgorithmSpec(
            algorithm_id="ml-dsa-87-v1",
            name="ML-DSA-87",
            algorithm_type=AlgorithmType.POST_QUANTUM_SIGNATURE,
            security_level=SecurityLevel.LEVEL_192,
            status=AlgorithmStatus.APPROVED,
            version="1.0",
            implementation="quantcrypt",
            compliance_standards=["NIST-FIPS-204"]
        ))
        
        # Key derivation functions
        self.register_algorithm(AlgorithmSpec(
            algorithm_id="argon2id-v1",
            name="Argon2id",
            algorithm_type=AlgorithmType.KEY_DERIVATION,
            security_level=SecurityLevel.LEVEL_128,
            status=AlgorithmStatus.APPROVED,
            version="1.0",
            implementation="nacl",
            parameters={"memory_cost": 262144, "time_cost": 3, "parallelism": 1}
        ))
        
        # Deprecated algorithms (for backward compatibility)
        self.register_algorithm(AlgorithmSpec(
            algorithm_id="aes-128-cbc-v1",
            name="AES-128-CBC",
            algorithm_type=AlgorithmType.SYMMETRIC_ENCRYPTION,
            security_level=SecurityLevel.LEVEL_128,
            status=AlgorithmStatus.DEPRECATED,
            version="1.0",
            implementation="cryptography",
            key_size=128,
            deprecation_date=time.time() + (365 * 24 * 3600),  # 1 year from now
            replacement_algorithm="aes-256-gcm-v1"
        ))
    
    def register_algorithm(self, spec: AlgorithmSpec):
        """Register a new algorithm specification"""
        # Store current version
        self.algorithms[spec.algorithm_id] = spec
        
        # Maintain version history
        base_id = spec.algorithm_id.split('-v')[0] if '-v' in spec.algorithm_id else spec.algorithm_id
        if base_id not in self.algorithm_history:
            self.algorithm_history[base_id] = []
        self.algorithm_history[base_id].append(spec)
    
    def get_algorithm(self, algorithm_id: str) -> Optional[AlgorithmSpec]:
        """Get algorithm specification by ID"""
        return self.algorithms.get(algorithm_id)
    
    def get_recommended_algorithm(self, 
                                 algorithm_type: AlgorithmType,
                                 security_level: SecurityLevel = SecurityLevel.LEVEL_256) -> Optional[AlgorithmSpec]:
        """Get recommended algorithm for given type and security level"""
        candidates = [
            spec for spec in self.algorithms.values()
            if (spec.algorithm_type == algorithm_type and 
                spec.security_level >= security_level and
                spec.status == AlgorithmStatus.APPROVED)
        ]
        
        # Sort by security level and prefer latest versions
        candidates.sort(key=lambda x: (x.security_level.value, x.version), reverse=True)
        
        return candidates[0] if candidates else None
    
    def get_migration_path(self, from_algorithm: str) -> Optional[str]:
        """Get migration path for deprecated algorithm"""
        spec = self.get_algorithm(from_algorithm)
        if spec and spec.replacement_algorithm:
            return spec.replacement_algorithm
        return self.migration_rules.get(from_algorithm)
    
    def is_algorithm_allowed(self, algorithm_id: str) -> bool:
        """Check if algorithm is allowed for use"""
        spec = self.get_algorithm(algorithm_id)
        return spec is not None and spec.status != AlgorithmStatus.PROHIBITED
    
    def list_algorithms_by_type(self, algorithm_type: AlgorithmType) -> List[AlgorithmSpec]:
        """List all algorithms of given type"""
        return [spec for spec in self.algorithms.values() 
                if spec.algorithm_type == algorithm_type]
    
    def get_deprecated_algorithms(self) -> List[AlgorithmSpec]:
        """Get list of deprecated algorithms"""
        return [spec for spec in self.algorithms.values() 
                if spec.status == AlgorithmStatus.DEPRECATED]


class CryptographicProtocol:
    """
    Base class for versioned cryptographic protocols
    """
    
    def __init__(self, registry: AlgorithmRegistry):
        """Initialize with algorithm registry"""
        self.registry = registry
        self.backend = default_backend()
    
    def create_context(self, algorithm_id: str, operation_id: str) -> CryptographicContext:
        """Create cryptographic context for operation"""
        spec = self.registry.get_algorithm(algorithm_id)
        if not spec:
            raise ValueError(f"Unknown algorithm: {algorithm_id}")
        
        if not self.registry.is_algorithm_allowed(algorithm_id):
            raise ValueError(f"Algorithm not allowed: {algorithm_id} (status: {spec.status.value})")
        
        return CryptographicContext(
            version="2.0",
            algorithm_spec=spec,
            operation_id=operation_id,
            timestamp=time.time()
        )
    
    def serialize_context(self, context: CryptographicContext) -> bytes:
        """Serialize cryptographic context"""
        context_dict = asdict(context)
        # Convert enum values to strings for JSON serialization
        context_dict['algorithm_spec']['algorithm_type'] = context.algorithm_spec.algorithm_type.value
        context_dict['algorithm_spec']['security_level'] = context.algorithm_spec.security_level.value
        context_dict['algorithm_spec']['status'] = context.algorithm_spec.status.value
        
        context_json = json.dumps(context_dict, sort_keys=True)
        return context_json.encode('utf-8')
    
    def deserialize_context(self, data: bytes) -> CryptographicContext:
        """Deserialize cryptographic context"""
        context_dict = json.loads(data.decode('utf-8'))
        
        # Convert string values back to enums
        context_dict['algorithm_spec']['algorithm_type'] = AlgorithmType(
            context_dict['algorithm_spec']['algorithm_type']
        )
        context_dict['algorithm_spec']['security_level'] = SecurityLevel(
            context_dict['algorithm_spec']['security_level']
        )
        context_dict['algorithm_spec']['status'] = AlgorithmStatus(
            context_dict['algorithm_spec']['status']
        )
        
        # Reconstruct the algorithm spec
        algorithm_spec = AlgorithmSpec(**context_dict['algorithm_spec'])
        
        return CryptographicContext(
            version=context_dict['version'],
            algorithm_spec=algorithm_spec,
            operation_id=context_dict['operation_id'],
            timestamp=context_dict['timestamp'],
            metadata=context_dict.get('metadata')
        )


class VersionedEncryption(CryptographicProtocol):
    """
    Versioned encryption with algorithm agility
    """
    
    def encrypt(self, data: bytes, 
                algorithm_id: Optional[str] = None,
                security_level: SecurityLevel = SecurityLevel.LEVEL_256) -> Dict[str, Any]:
        """
        Encrypt data with algorithm versioning
        """
        # Select algorithm if not specified
        if not algorithm_id:
            spec = self.registry.get_recommended_algorithm(
                AlgorithmType.SYMMETRIC_ENCRYPTION, 
                security_level
            )
            if not spec:
                raise ValueError("No suitable encryption algorithm available")
            algorithm_id = spec.algorithm_id
        
        # Create context
        context = self.create_context(algorithm_id, "encrypt")
        
        # Encrypt based on algorithm
        if context.algorithm_spec.name == "AES-256-GCM":
            encrypted_data = self._encrypt_aes_gcm(data, context)
        elif context.algorithm_spec.name == "ChaCha20-Poly1305":
            encrypted_data = self._encrypt_chacha20_poly1305(data, context)
        else:
            raise ValueError(f"Unsupported encryption algorithm: {context.algorithm_spec.name}")
        
        # Add versioning information
        encrypted_data['context'] = self.serialize_context(context)
        encrypted_data['format_version'] = "2.0"
        
        return encrypted_data
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data with version compatibility
        """
        # Check format version
        format_version = encrypted_data.get('format_version', '1.0')
        
        if format_version == "2.0":
            return self._decrypt_v2(encrypted_data)
        elif format_version == "1.0":
            return self._decrypt_v1(encrypted_data)
        else:
            raise ValueError(f"Unsupported format version: {format_version}")
    
    def _decrypt_v2(self, encrypted_data: Dict[str, Any]) -> bytes:
        """Decrypt version 2.0 format"""
        # Deserialize context
        context = self.deserialize_context(encrypted_data['context'])
        
        # Check if algorithm is still allowed
        if not self.registry.is_algorithm_allowed(context.algorithm_spec.algorithm_id):
            spec = self.registry.get_algorithm(context.algorithm_spec.algorithm_id)
            if spec and spec.status == AlgorithmStatus.DEPRECATED:
                print(f"Warning: Using deprecated algorithm {context.algorithm_spec.algorithm_id}")
            else:
                raise ValueError(f"Algorithm prohibited: {context.algorithm_spec.algorithm_id}")
        
        # Decrypt based on algorithm
        if context.algorithm_spec.name == "AES-256-GCM":
            return self._decrypt_aes_gcm(encrypted_data, context)
        elif context.algorithm_spec.name == "ChaCha20-Poly1305":
            return self._decrypt_chacha20_poly1305(encrypted_data, context)
        else:
            raise ValueError(f"Unsupported algorithm: {context.algorithm_spec.name}")
    
    def _decrypt_v1(self, encrypted_data: Dict[str, Any]) -> bytes:
        """Decrypt legacy version 1.0 format"""
        # Legacy decryption logic - simplified for example
        algorithm = encrypted_data.get('algorithm', 'aes-256-gcm')
        
        if algorithm == 'aes-256-gcm':
            # Create a legacy context
            spec = self.registry.get_algorithm('aes-256-gcm-v1')
            if spec:
                context = CryptographicContext(
                    version="1.0",
                    algorithm_spec=spec,
                    operation_id="legacy_decrypt",
                    timestamp=time.time()
                )
                return self._decrypt_aes_gcm(encrypted_data, context)
        
        raise ValueError(f"Unsupported legacy algorithm: {algorithm}")
    
    def _encrypt_aes_gcm(self, data: bytes, context: CryptographicContext) -> Dict[str, Any]:
        """Encrypt using AES-256-GCM"""
        key = nacl.utils.random(32)  # 256-bit key
        iv = nacl.utils.random(12)   # 96-bit IV for GCM
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return {
            'algorithm': context.algorithm_spec.algorithm_id,
            'key': key,
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag
        }
    
    def _decrypt_aes_gcm(self, encrypted_data: Dict[str, Any], 
                        context: CryptographicContext) -> bytes:
        """Decrypt using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(encrypted_data['key']),
            modes.GCM(encrypted_data['iv'], encrypted_data['tag']),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
    
    def _encrypt_chacha20_poly1305(self, data: bytes, 
                                  context: CryptographicContext) -> Dict[str, Any]:
        """Encrypt using ChaCha20-Poly1305"""
        key = nacl.utils.random(32)  # 256-bit key
        box = nacl.secret.SecretBox(key)
        encrypted = box.encrypt(data)
        
        # Extract nonce and ciphertext
        nonce = encrypted[:nacl.secret.SecretBox.NONCE_SIZE]
        ciphertext = encrypted[nacl.secret.SecretBox.NONCE_SIZE:]
        
        return {
            'algorithm': context.algorithm_spec.algorithm_id,
            'key': key,
            'nonce': nonce,
            'ciphertext': ciphertext
        }
    
    def _decrypt_chacha20_poly1305(self, encrypted_data: Dict[str, Any], 
                                  context: CryptographicContext) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        box = nacl.secret.SecretBox(encrypted_data['key'])
        
        # Reconstruct NaCl format
        nacl_encrypted = encrypted_data['nonce'] + encrypted_data['ciphertext']
        
        return box.decrypt(nacl_encrypted)


class AlgorithmMigrationManager:
    """
    Manages migration between algorithm versions
    """
    
    def __init__(self, registry: AlgorithmRegistry):
        """Initialize migration manager"""
        self.registry = registry
        self.encryption = VersionedEncryption(registry)
    
    def migrate_encrypted_data(self, encrypted_data: Dict[str, Any], 
                              target_algorithm: Optional[str] = None) -> Dict[str, Any]:
        """
        Migrate encrypted data to newer algorithm
        """
        # Decrypt with old algorithm
        plaintext = self.encryption.decrypt(encrypted_data)
        
        # Get target algorithm
        if not target_algorithm:
            # Find recommended replacement
            if 'context' in encrypted_data:
                old_context = self.encryption.deserialize_context(encrypted_data['context'])
                migration_target = self.registry.get_migration_path(
                    old_context.algorithm_spec.algorithm_id
                )
                if migration_target:
                    target_algorithm = migration_target
        
        if not target_algorithm:
            # Use current recommendation
            spec = self.registry.get_recommended_algorithm(
                AlgorithmType.SYMMETRIC_ENCRYPTION
            )
            target_algorithm = spec.algorithm_id if spec else None
        
        if not target_algorithm:
            raise ValueError("No suitable target algorithm for migration")
        
        # Encrypt with new algorithm
        return self.encryption.encrypt(plaintext, target_algorithm)
    
    def check_migration_needed(self, encrypted_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Check if migration is needed for encrypted data
        Returns: (needs_migration, reason)
        """
        if 'context' not in encrypted_data:
            return True, "Legacy format without context"
        
        context = self.encryption.deserialize_context(encrypted_data['context'])
        spec = context.algorithm_spec
        
        if spec.status == AlgorithmStatus.PROHIBITED:
            return True, f"Algorithm {spec.algorithm_id} is prohibited"
        
        if spec.status == AlgorithmStatus.DEPRECATED:
            if spec.deprecation_date and time.time() > spec.deprecation_date:
                return True, f"Algorithm {spec.algorithm_id} has expired"
            return False, f"Algorithm {spec.algorithm_id} is deprecated but not expired"
        
        return False, None
    
    def batch_migrate(self, encrypted_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Batch migrate multiple encrypted items
        """
        migrated_items = []
        
        for item in encrypted_items:
            needs_migration, reason = self.check_migration_needed(item)
            
            if needs_migration:
                try:
                    migrated_item = self.migrate_encrypted_data(item)
                    migrated_items.append(migrated_item)
                    print(f"Migrated item: {reason}")
                except Exception as e:
                    print(f"Failed to migrate item: {e}")
                    migrated_items.append(item)  # Keep original on failure
            else:
                migrated_items.append(item)
        
        return migrated_items


# Global algorithm registry instance
_global_registry = AlgorithmRegistry()

def get_algorithm_registry() -> AlgorithmRegistry:
    """Get global algorithm registry instance"""
    return _global_registry

def create_versioned_encryption() -> VersionedEncryption:
    """Create versioned encryption instance"""
    return VersionedEncryption(_global_registry)

def create_migration_manager() -> AlgorithmMigrationManager:
    """Create algorithm migration manager"""
    return AlgorithmMigrationManager(_global_registry)