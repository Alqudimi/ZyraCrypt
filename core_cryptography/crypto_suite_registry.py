"""
Cryptographic Suite Registry and Versioned Container System

This module provides algorithm agility and versioning for cryptographic operations,
enabling backward compatibility and seamless algorithm transitions.
"""

import json
import struct
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict
from enum import Enum
import time


class CryptoVersion(Enum):
    """Supported cryptographic protocol versions."""
    V1_0 = "1.0"
    V1_1 = "1.1"
    V2_0 = "2.0"
    
    @classmethod
    def latest(cls):
        return cls.V2_0
    
    @classmethod
    def from_string(cls, version: str):
        for v in cls:
            if v.value == version:
                return v
        raise ValueError(f"Unsupported version: {version}")


@dataclass
class CryptoSuite:
    """Defines a cryptographic algorithm suite configuration."""
    suite_id: str
    version: CryptoVersion
    key_exchange: str  # "X25519", "Kyber768", "X25519+Kyber768"
    signature: str     # "Ed25519", "Dilithium3", "Ed25519+Dilithium3"
    symmetric: str     # "AES-256-GCM", "ChaCha20-Poly1305"
    kdf: str          # "HKDF-SHA256", "Argon2id"
    hash_algo: str    # "SHA256", "SHA3-256"
    deprecated: bool = False
    min_security_level: int = 128  # bits
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert suite to dictionary for serialization."""
        result = asdict(self)
        result['version'] = self.version.value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CryptoSuite':
        """Create suite from dictionary."""
        data['version'] = CryptoVersion.from_string(data['version'])
        return cls(**data)


@dataclass
class EnvelopeHeader:
    """Cryptographic envelope header with metadata."""
    version: CryptoVersion
    suite_id: str
    timestamp: float
    sender_kid: Optional[str] = None
    recipient_kid: Optional[str] = None
    nonce: Optional[bytes] = None
    additional_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert header to dictionary for serialization."""
        result = asdict(self)
        result['version'] = self.version.value
        if self.nonce:
            result['nonce'] = self.nonce.hex()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EnvelopeHeader':
        """Create header from dictionary."""
        data['version'] = CryptoVersion.from_string(data['version'])
        if 'nonce' in data and data['nonce']:
            data['nonce'] = bytes.fromhex(data['nonce'])
        return cls(**data)


@dataclass
class CryptographicEnvelope:
    """Versioned cryptographic container format."""
    header: EnvelopeHeader
    payload: bytes
    authentication_tag: bytes
    
    def serialize(self) -> bytes:
        """Serialize envelope to binary format."""
        # Create the envelope structure:
        # [MAGIC][VERSION][HEADER_LEN][HEADER][PAYLOAD_LEN][PAYLOAD][TAG]
        
        magic = b'ALQD'  # Magic bytes for format identification
        version_bytes = struct.pack('!H', int(float(self.header.version.value) * 10))
        
        header_json = json.dumps(self.header.to_dict()).encode('utf-8')
        header_len = struct.pack('!I', len(header_json))
        
        payload_len = struct.pack('!I', len(self.payload))
        
        return (magic + version_bytes + header_len + header_json + 
                payload_len + self.payload + self.authentication_tag)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'CryptographicEnvelope':
        """Deserialize envelope from binary format."""
        if len(data) < 14:  # Minimum size check
            raise ValueError("Invalid envelope format: too short")
        
        # Parse magic bytes
        if data[:4] != b'ALQD':
            raise ValueError("Invalid envelope format: wrong magic bytes")
        
        offset = 4
        
        # Parse version
        version_int = struct.unpack('!H', data[offset:offset+2])[0]
        version = CryptoVersion.from_string(str(version_int / 10))
        offset += 2
        
        # Parse header
        header_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        
        header_json = data[offset:offset+header_len].decode('utf-8')
        header_dict = json.loads(header_json)
        header = EnvelopeHeader.from_dict(header_dict)
        offset += header_len
        
        # Parse payload
        payload_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        
        payload = data[offset:offset+payload_len]
        offset += payload_len
        
        # Parse authentication tag
        auth_tag = data[offset:]
        
        return cls(header=header, payload=payload, authentication_tag=auth_tag)


class CryptoSuiteRegistry:
    """Registry for managing cryptographic algorithm suites."""
    
    def __init__(self):
        self._suites: Dict[str, CryptoSuite] = {}
        self._default_suites_initialized = False
        self._initialize_default_suites()
    
    def _initialize_default_suites(self):
        """Initialize default cryptographic suites."""
        if self._default_suites_initialized:
            return
        
        # Classical cryptography suites
        self.register_suite(CryptoSuite(
            suite_id="CLASSIC_HIGH",
            version=CryptoVersion.V1_0,
            key_exchange="X25519",
            signature="Ed25519",
            symmetric="AES-256-GCM",
            kdf="HKDF-SHA256",
            hash_algo="SHA256",
            min_security_level=128
        ))
        
        self.register_suite(CryptoSuite(
            suite_id="CLASSIC_CHACHA",
            version=CryptoVersion.V1_0,
            key_exchange="X25519",
            signature="Ed25519",
            symmetric="ChaCha20-Poly1305",
            kdf="HKDF-SHA256",
            hash_algo="SHA256",
            min_security_level=128
        ))
        
        # Post-Quantum suites
        self.register_suite(CryptoSuite(
            suite_id="PQC_HYBRID_MEDIUM",
            version=CryptoVersion.V2_0,
            key_exchange="X25519+Kyber768",
            signature="Ed25519+Dilithium3",
            symmetric="AES-256-GCM",
            kdf="HKDF-SHA256",
            hash_algo="SHA256",
            min_security_level=192
        ))
        
        self.register_suite(CryptoSuite(
            suite_id="PQC_HYBRID_HIGH",
            version=CryptoVersion.V2_0,
            key_exchange="X25519+Kyber1024",
            signature="Ed25519+Dilithium5",
            symmetric="AES-256-GCM",
            kdf="HKDF-SHA256",
            hash_algo="SHA256",
            min_security_level=256
        ))
        
        # Pure Post-Quantum suites
        self.register_suite(CryptoSuite(
            suite_id="PQC_PURE_HIGH",
            version=CryptoVersion.V2_0,
            key_exchange="Kyber1024",
            signature="Dilithium5",
            symmetric="AES-256-GCM",
            kdf="HKDF-SHA256",
            hash_algo="SHA3-256",
            min_security_level=256
        ))
        
        # Enhanced KDF suites
        self.register_suite(CryptoSuite(
            suite_id="ENHANCED_KDF",
            version=CryptoVersion.V1_1,
            key_exchange="X25519",
            signature="Ed25519",
            symmetric="AES-256-GCM",
            kdf="Argon2id",
            hash_algo="SHA256",
            min_security_level=128
        ))
        
        self._default_suites_initialized = True
    
    def register_suite(self, suite: CryptoSuite):
        """Register a new cryptographic suite."""
        self._suites[suite.suite_id] = suite
    
    def get_suite(self, suite_id: str) -> Optional[CryptoSuite]:
        """Get a cryptographic suite by ID."""
        return self._suites.get(suite_id)
    
    def list_suites(self, include_deprecated: bool = False) -> List[CryptoSuite]:
        """List all available cryptographic suites."""
        suites = list(self._suites.values())
        if not include_deprecated:
            suites = [s for s in suites if not s.deprecated]
        return sorted(suites, key=lambda x: (x.min_security_level, x.suite_id))
    
    def deprecate_suite(self, suite_id: str):
        """Mark a suite as deprecated."""
        if suite_id in self._suites:
            self._suites[suite_id].deprecated = True
    
    def get_default_suite(self, security_level: int = 128) -> CryptoSuite:
        """Get the default suite for a given security level."""
        suitable_suites = [
            s for s in self._suites.values() 
            if not s.deprecated and s.min_security_level <= security_level
        ]
        
        if not suitable_suites:
            raise ValueError(f"No suitable suite for security level {security_level}")
        
        # Return the highest security level suite that meets requirements
        return max(suitable_suites, key=lambda x: x.min_security_level)
    
    def get_hybrid_pqc_suite(self, security_level: int = 192) -> CryptoSuite:
        """Get a hybrid post-quantum cryptography suite."""
        hybrid_suites = [
            s for s in self._suites.values()
            if not s.deprecated and '+' in s.key_exchange and s.min_security_level <= security_level
        ]
        
        if not hybrid_suites:
            raise ValueError(f"No hybrid PQC suite available for security level {security_level}")
        
        return max(hybrid_suites, key=lambda x: x.min_security_level)
    
    def is_compatible(self, suite_id: str, version: CryptoVersion) -> bool:
        """Check if a suite is compatible with a protocol version."""
        suite = self.get_suite(suite_id)
        if not suite:
            return False
        
        # Version compatibility rules
        if version == CryptoVersion.V1_0:
            return not ('+' in suite.key_exchange or '+' in suite.signature)
        elif version == CryptoVersion.V1_1:
            return suite.version in [CryptoVersion.V1_0, CryptoVersion.V1_1]
        else:  # V2_0 and later
            return True
    
    def create_envelope(self, suite_id: str, payload: bytes, auth_tag: bytes,
                       sender_kid: Optional[str] = None, 
                       recipient_kid: Optional[str] = None,
                       additional_data: Optional[Dict[str, Any]] = None) -> CryptographicEnvelope:
        """Create a cryptographic envelope with the specified suite."""
        suite = self.get_suite(suite_id)
        if not suite:
            raise ValueError(f"Unknown suite: {suite_id}")
        
        header = EnvelopeHeader(
            version=suite.version,
            suite_id=suite_id,
            timestamp=time.time(),
            sender_kid=sender_kid,
            recipient_kid=recipient_kid,
            additional_data=additional_data
        )
        
        return CryptographicEnvelope(
            header=header,
            payload=payload,
            authentication_tag=auth_tag
        )


# Global registry instance
registry = CryptoSuiteRegistry()