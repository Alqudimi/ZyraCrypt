"""
Enhanced Key Derivation Functions and Password Schemes
Implements latest security standards with side-channel resistance
Supports Argon2, scrypt, PBKDF2, and HKDF with optimal parameters
"""

import os
import time
import hashlib
import secrets
import struct
from typing import Dict, Optional, Tuple, Any, Union
from dataclasses import dataclass
from enum import Enum

# Enhanced cryptographic libraries
import nacl.pwhash
import nacl.secret
import nacl.utils
import nacl.encoding
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Password strength analysis
try:
    import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False


class KDFAlgorithm(Enum):
    """Supported KDF algorithms"""
    ARGON2ID = "argon2id"          # Recommended for password hashing
    ARGON2I = "argon2i"            # For side-channel resistance
    SCRYPT = "scrypt"              # Memory-hard function
    PBKDF2_SHA256 = "pbkdf2_sha256"  # FIPS approved
    PBKDF2_SHA512 = "pbkdf2_sha512"  # Enhanced security
    HKDF_SHA256 = "hkdf_sha256"    # For key expansion


class SecurityProfile(Enum):
    """Security profiles with different resource requirements"""
    INTERACTIVE = "interactive"    # For real-time authentication
    SENSITIVE = "sensitive"        # For high-value data
    PARANOID = "paranoid"         # Maximum security regardless of cost


@dataclass
class KDFParameters:
    """Parameters for key derivation functions"""
    algorithm: KDFAlgorithm
    iterations: Optional[int] = None
    memory_cost: Optional[int] = None
    parallelism: Optional[int] = None
    salt_length: int = 32
    key_length: int = 32
    security_profile: SecurityProfile = SecurityProfile.SENSITIVE


@dataclass
class PasswordPolicy:
    """Password policy configuration"""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_symbols: bool = True
    forbidden_patterns: list = None
    min_entropy_bits: float = 50.0
    check_common_passwords: bool = True


@dataclass
class DerivedKeyMaterial:
    """Container for derived key material"""
    key: bytes
    salt: bytes
    algorithm: KDFAlgorithm
    parameters: Dict[str, Any]
    timestamp: float
    version: str = "2.0"


class EnhancedKDF:
    """
    Enhanced Key Derivation Function implementation
    Provides optimal security parameters and side-channel resistance
    """
    
    # Recommended parameters for different security profiles
    ARGON2ID_PARAMS = {
        SecurityProfile.INTERACTIVE: {
            'memory_cost': 65536,      # 64 MB
            'time_cost': 2,            # 2 iterations
            'parallelism': 1
        },
        SecurityProfile.SENSITIVE: {
            'memory_cost': 262144,     # 256 MB
            'time_cost': 3,            # 3 iterations
            'parallelism': 1
        },
        SecurityProfile.PARANOID: {
            'memory_cost': 1048576,    # 1 GB
            'time_cost': 4,            # 4 iterations
            'parallelism': 1
        }
    }
    
    SCRYPT_PARAMS = {
        SecurityProfile.INTERACTIVE: {
            'n': 32768,      # 2^15
            'r': 8,
            'p': 1
        },
        SecurityProfile.SENSITIVE: {
            'n': 131072,     # 2^17
            'r': 8,
            'p': 1
        },
        SecurityProfile.PARANOID: {
            'n': 1048576,    # 2^20
            'r': 8,
            'p': 1
        }
    }
    
    PBKDF2_PARAMS = {
        SecurityProfile.INTERACTIVE: {
            'iterations': 210000     # OWASP 2023 recommendation
        },
        SecurityProfile.SENSITIVE: {
            'iterations': 600000     # Enhanced security
        },
        SecurityProfile.PARANOID: {
            'iterations': 1200000    # Maximum security
        }
    }
    
    def __init__(self):
        """Initialize enhanced KDF"""
        self.backend = default_backend()
    
    def derive_key(self, 
                   password: Union[str, bytes], 
                   salt: Optional[bytes] = None,
                   algorithm: KDFAlgorithm = KDFAlgorithm.ARGON2ID,
                   security_profile: SecurityProfile = SecurityProfile.SENSITIVE,
                   key_length: int = 32) -> DerivedKeyMaterial:
        """
        Derive key from password using specified algorithm and security profile
        """
        # Convert password to bytes if needed
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
        
        # Generate salt if not provided
        if salt is None:
            salt = nacl.utils.random(32)
        
        # Derive key based on algorithm
        if algorithm == KDFAlgorithm.ARGON2ID:
            key, params = self._derive_argon2id(password_bytes, salt, security_profile, key_length)
        elif algorithm == KDFAlgorithm.ARGON2I:
            key, params = self._derive_argon2i(password_bytes, salt, security_profile, key_length)
        elif algorithm == KDFAlgorithm.SCRYPT:
            key, params = self._derive_scrypt(password_bytes, salt, security_profile, key_length)
        elif algorithm == KDFAlgorithm.PBKDF2_SHA256:
            key, params = self._derive_pbkdf2_sha256(password_bytes, salt, security_profile, key_length)
        elif algorithm == KDFAlgorithm.PBKDF2_SHA512:
            key, params = self._derive_pbkdf2_sha512(password_bytes, salt, security_profile, key_length)
        elif algorithm == KDFAlgorithm.HKDF_SHA256:
            key, params = self._derive_hkdf_sha256(password_bytes, salt, key_length)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        return DerivedKeyMaterial(
            key=key,
            salt=salt,
            algorithm=algorithm,
            parameters=params,
            timestamp=time.time()
        )
    
    def _derive_argon2id(self, password: bytes, salt: bytes, 
                        security_profile: SecurityProfile, key_length: int) -> Tuple[bytes, Dict]:
        """Derive key using Argon2id (recommended)"""
        params = self.ARGON2ID_PARAMS[security_profile]
        
        # PyNaCl requires 16-byte salt for Argon2
        if len(salt) != 16:
            # Truncate or pad salt to 16 bytes
            if len(salt) > 16:
                salt = salt[:16]
            else:
                salt = salt + b'\x00' * (16 - len(salt))
        
        # Use PyNaCl's Argon2id implementation
        try:
            key = nacl.pwhash.argon2id.kdf(
                size=key_length,
                password=password,
                salt=salt,
                opslimit=params['time_cost'],
                memlimit=params['memory_cost']
            )
        except Exception as e:
            # Fallback to Argon2i if Argon2id not available
            key = nacl.pwhash.argon2i.kdf(
                size=key_length,
                password=password,
                salt=salt,
                opslimit=params['time_cost'],
                memlimit=params['memory_cost']
            )
        
        return key, params
    
    def _derive_argon2i(self, password: bytes, salt: bytes, 
                       security_profile: SecurityProfile, key_length: int) -> Tuple[bytes, Dict]:
        """Derive key using Argon2i (side-channel resistant)"""
        params = self.ARGON2ID_PARAMS[security_profile]  # Same params as Argon2id
        
        # PyNaCl requires 16-byte salt for Argon2
        if len(salt) != 16:
            if len(salt) > 16:
                salt = salt[:16]
            else:
                salt = salt + b'\x00' * (16 - len(salt))
        
        key = nacl.pwhash.argon2i.kdf(
            size=key_length,
            password=password,
            salt=salt,
            opslimit=params['time_cost'],
            memlimit=params['memory_cost']
        )
        
        return key, params
    
    def _derive_scrypt(self, password: bytes, salt: bytes, 
                      security_profile: SecurityProfile, key_length: int) -> Tuple[bytes, Dict]:
        """Derive key using scrypt"""
        params = self.SCRYPT_PARAMS[security_profile]
        
        kdf = Scrypt(
            length=key_length,
            salt=salt,
            n=params['n'],
            r=params['r'],
            p=params['p'],
            backend=self.backend
        )
        
        key = kdf.derive(password)
        return key, params
    
    def _derive_pbkdf2_sha256(self, password: bytes, salt: bytes, 
                             security_profile: SecurityProfile, key_length: int) -> Tuple[bytes, Dict]:
        """Derive key using PBKDF2-SHA256"""
        params = self.PBKDF2_PARAMS[security_profile]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=params['iterations'],
            backend=self.backend
        )
        
        key = kdf.derive(password)
        return key, params
    
    def _derive_pbkdf2_sha512(self, password: bytes, salt: bytes, 
                             security_profile: SecurityProfile, key_length: int) -> Tuple[bytes, Dict]:
        """Derive key using PBKDF2-SHA512"""
        params = self.PBKDF2_PARAMS[security_profile]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=salt,
            iterations=params['iterations'],
            backend=self.backend
        )
        
        key = kdf.derive(password)
        return key, params
    
    def _derive_hkdf_sha256(self, input_key: bytes, salt: bytes, key_length: int) -> Tuple[bytes, Dict]:
        """Derive key using HKDF-SHA256 (for key expansion, not password hashing)"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=b'Enhanced-KDF-v2.0',
            backend=self.backend
        )
        
        key = hkdf.derive(input_key)
        params = {'hash_algorithm': 'SHA256', 'info': 'Enhanced-KDF-v2.0'}
        
        return key, params
    
    def verify_derived_key(self, password: Union[str, bytes], 
                          derived_material: DerivedKeyMaterial) -> bool:
        """
        Verify a password against derived key material
        Uses constant-time comparison to prevent timing attacks
        """
        # Convert password to bytes if needed
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
        
        # Re-derive the key with same parameters
        try:
            if derived_material.algorithm == KDFAlgorithm.ARGON2ID:
                # PyNaCl requires 16-byte salt
                salt = derived_material.salt
                if len(salt) != 16:
                    if len(salt) > 16:
                        salt = salt[:16]
                    else:
                        salt = salt + b'\x00' * (16 - len(salt))
                        
                test_key = nacl.pwhash.argon2id.kdf(
                    size=len(derived_material.key),
                    password=password_bytes,
                    salt=salt,
                    opslimit=derived_material.parameters['time_cost'],
                    memlimit=derived_material.parameters['memory_cost']
                )
            elif derived_material.algorithm == KDFAlgorithm.ARGON2I:
                # PyNaCl requires 16-byte salt
                salt = derived_material.salt
                if len(salt) != 16:
                    if len(salt) > 16:
                        salt = salt[:16]
                    else:
                        salt = salt + b'\x00' * (16 - len(salt))
                        
                test_key = nacl.pwhash.argon2i.kdf(
                    size=len(derived_material.key),
                    password=password_bytes,
                    salt=salt,
                    opslimit=derived_material.parameters['time_cost'],
                    memlimit=derived_material.parameters['memory_cost']
                )
            elif derived_material.algorithm == KDFAlgorithm.SCRYPT:
                kdf = Scrypt(
                    length=len(derived_material.key),
                    salt=derived_material.salt,
                    n=derived_material.parameters['n'],
                    r=derived_material.parameters['r'],
                    p=derived_material.parameters['p'],
                    backend=self.backend
                )
                test_key = kdf.derive(password_bytes)
            elif derived_material.algorithm in [KDFAlgorithm.PBKDF2_SHA256, KDFAlgorithm.PBKDF2_SHA512]:
                hash_algo = hashes.SHA256() if derived_material.algorithm == KDFAlgorithm.PBKDF2_SHA256 else hashes.SHA512()
                kdf = PBKDF2HMAC(
                    algorithm=hash_algo,
                    length=len(derived_material.key),
                    salt=derived_material.salt,
                    iterations=derived_material.parameters['iterations'],
                    backend=self.backend
                )
                test_key = kdf.derive(password_bytes)
            else:
                return False
            
            # Use constant-time comparison
            return constant_time.bytes_eq(derived_material.key, test_key)
            
        except Exception:
            return False


class PasswordValidator:
    """
    Advanced password validation with entropy analysis
    """
    
    def __init__(self, policy: Optional[PasswordPolicy] = None):
        """Initialize with password policy"""
        self.policy = policy or PasswordPolicy()
        
        # Common passwords list (sample - in production use a comprehensive list)
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        }
    
    def validate_password(self, password: str) -> Dict[str, Any]:
        """
        Comprehensive password validation
        Returns validation results with recommendations
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'strength_score': 0,
            'entropy_bits': 0,
            'recommendations': []
        }
        
        # Basic length checks
        if len(password) < self.policy.min_length:
            results['valid'] = False
            results['errors'].append(f"Password must be at least {self.policy.min_length} characters")
        
        if len(password) > self.policy.max_length:
            results['valid'] = False
            results['errors'].append(f"Password must be no more than {self.policy.max_length} characters")
        
        # Character class requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        if self.policy.require_uppercase and not has_upper:
            results['valid'] = False
            results['errors'].append("Password must contain uppercase letters")
        
        if self.policy.require_lowercase and not has_lower:
            results['valid'] = False
            results['errors'].append("Password must contain lowercase letters")
        
        if self.policy.require_digits and not has_digit:
            results['valid'] = False
            results['errors'].append("Password must contain digits")
        
        if self.policy.require_symbols and not has_symbol:
            results['valid'] = False
            results['errors'].append("Password must contain symbols")
        
        # Check against common passwords
        if self.policy.check_common_passwords and password.lower() in self.common_passwords:
            results['valid'] = False
            results['errors'].append("Password is too common")
        
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        results['entropy_bits'] = entropy
        
        if entropy < self.policy.min_entropy_bits:
            results['valid'] = False
            results['errors'].append(f"Password entropy too low ({entropy:.1f} bits, need {self.policy.min_entropy_bits})")
        
        # Use zxcvbn for advanced analysis if available
        if ZXCVBN_AVAILABLE:
            zxcvbn_result = zxcvbn.zxcvbn(password)
            results['strength_score'] = zxcvbn_result['score']
            results['crack_time'] = zxcvbn_result['crack_times_display']['offline_slow_hashing_1e4_per_second']
            
            if zxcvbn_result['feedback']['suggestions']:
                results['recommendations'].extend(zxcvbn_result['feedback']['suggestions'])
        
        # Additional recommendations
        if len(password) < 16:
            results['recommendations'].append("Consider using a longer password (16+ characters)")
        
        if not has_symbol:
            results['recommendations'].append("Add special characters for better security")
        
        return results
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy in bits
        Uses character set size and frequency analysis
        """
        if not password:
            return 0.0
        
        # Determine character set size
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26  # lowercase
        if any(c.isupper() for c in password):
            charset_size += 26  # uppercase
        if any(c.isdigit() for c in password):
            charset_size += 10  # digits
        if any(not c.isalnum() for c in password):
            charset_size += 32  # common symbols
        
        # Calculate frequency-based entropy
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        password_length = len(password)
        
        import math
        for count in char_counts.values():
            probability = count / password_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Combine with character set entropy
        charset_entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        
        # Return conservative estimate
        return min(entropy * password_length, charset_entropy)
    
    def generate_secure_password(self, length: int = 16, 
                                include_symbols: bool = True) -> str:
        """
        Generate a cryptographically secure password
        """
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?' if include_symbols else ''
        
        # Build character set
        charset = lowercase + uppercase + digits + symbols
        
        # Ensure at least one character from each required class
        password_chars = []
        
        if self.policy.require_lowercase:
            password_chars.append(secrets.choice(lowercase))
        if self.policy.require_uppercase:
            password_chars.append(secrets.choice(uppercase))
        if self.policy.require_digits:
            password_chars.append(secrets.choice(digits))
        if self.policy.require_symbols and include_symbols:
            password_chars.append(secrets.choice(symbols))
        
        # Fill remaining length
        remaining_length = length - len(password_chars)
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(charset))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)


class SecurePasswordStore:
    """
    Secure password storage using enhanced KDF
    """
    
    def __init__(self, 
                 algorithm: KDFAlgorithm = KDFAlgorithm.ARGON2ID,
                 security_profile: SecurityProfile = SecurityProfile.SENSITIVE):
        """Initialize secure password store"""
        self.kdf = EnhancedKDF()
        self.algorithm = algorithm
        self.security_profile = security_profile
        self.validator = PasswordValidator()
    
    def hash_password(self, password: str) -> str:
        """
        Hash password for secure storage
        Returns serialized derived key material
        """
        # Validate password first
        validation = self.validator.validate_password(password)
        if not validation['valid']:
            raise ValueError(f"Password validation failed: {validation['errors']}")
        
        # Derive key material
        derived = self.kdf.derive_key(
            password=password,
            algorithm=self.algorithm,
            security_profile=self.security_profile
        )
        
        # Serialize for storage
        return self._serialize_derived_material(derived)
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Verify password against stored hash
        """
        try:
            # Deserialize stored material
            derived = self._deserialize_derived_material(stored_hash)
            
            # Verify using KDF
            return self.kdf.verify_derived_key(password, derived)
        except Exception:
            return False
    
    def _serialize_derived_material(self, derived: DerivedKeyMaterial) -> str:
        """Serialize derived key material for storage"""
        data = {
            'key': nacl.encoding.Base64Encoder.encode(derived.key).decode(),
            'salt': nacl.encoding.Base64Encoder.encode(derived.salt).decode(),
            'algorithm': derived.algorithm.value,
            'parameters': derived.parameters,
            'timestamp': derived.timestamp,
            'version': derived.version
        }
        
        import json
        return json.dumps(data)
    
    def _deserialize_derived_material(self, serialized: str) -> DerivedKeyMaterial:
        """Deserialize derived key material from storage"""
        import json
        data = json.loads(serialized)
        
        return DerivedKeyMaterial(
            key=nacl.encoding.Base64Encoder.decode(data['key']),
            salt=nacl.encoding.Base64Encoder.decode(data['salt']),
            algorithm=KDFAlgorithm(data['algorithm']),
            parameters=data['parameters'],
            timestamp=data['timestamp'],
            version=data['version']
        )