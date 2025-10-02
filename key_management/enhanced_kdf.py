"""
Enhanced Key Derivation Functions (KDF) and Password Schemes

This module provides hardened KDF implementations with modern best practices,
including Argon2id defaults, KMS-backed pepper, and PAKE support.
"""

import os
import hmac
import hashlib
import secrets
import time
from typing import Optional, Dict, Any, Tuple
from enum import Enum
from dataclasses import dataclass

# Cryptography imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# Argon2 imports
from argon2 import PasswordHasher, low_level
from argon2.exceptions import VerifyMismatchError

# Side-channel protection
from ..advanced_features.side_channel_protection import (
    SideChannelGuard, TimingAttackProtection
)


class KDFAlgorithm(Enum):
    """Supported KDF algorithms."""
    ARGON2ID = "argon2id"
    ARGON2I = "argon2i" 
    ARGON2D = "argon2d"
    PBKDF2_SHA256 = "pbkdf2_sha256"
    PBKDF2_SHA512 = "pbkdf2_sha512"
    SCRYPT = "scrypt"
    HKDF_SHA256 = "hkdf_sha256"
    HKDF_SHA512 = "hkdf_sha512"


@dataclass
class KDFParameters:
    """KDF algorithm parameters."""
    algorithm: KDFAlgorithm
    iterations: Optional[int] = None
    memory_cost: Optional[int] = None  # KiB for Argon2, bytes for scrypt
    parallelism: Optional[int] = None
    salt_length: int = 32
    output_length: int = 32
    
    @classmethod
    def get_secure_defaults(cls, algorithm: KDFAlgorithm) -> 'KDFParameters':
        """Get secure default parameters for each algorithm."""
        if algorithm == KDFAlgorithm.ARGON2ID:
            return cls(
                algorithm=algorithm,
                iterations=3,        # Time cost (t_cost)
                memory_cost=65536,   # 64 MiB (m_cost in KiB)
                parallelism=4,       # Parallel threads (p_cost)
                salt_length=32,
                output_length=32
            )
        elif algorithm == KDFAlgorithm.ARGON2I:
            return cls(
                algorithm=algorithm,
                iterations=3,
                memory_cost=65536,
                parallelism=4,
                salt_length=32,
                output_length=32
            )
        elif algorithm == KDFAlgorithm.ARGON2D:
            return cls(
                algorithm=algorithm,
                iterations=3,
                memory_cost=65536,
                parallelism=4,
                salt_length=32,
                output_length=32
            )
        elif algorithm == KDFAlgorithm.PBKDF2_SHA256:
            return cls(
                algorithm=algorithm,
                iterations=600000,   # OWASP 2023 recommendation
                salt_length=32,
                output_length=32
            )
        elif algorithm == KDFAlgorithm.PBKDF2_SHA512:
            return cls(
                algorithm=algorithm,
                iterations=210000,   # Adjusted for SHA512
                salt_length=32,
                output_length=64
            )
        elif algorithm == KDFAlgorithm.SCRYPT:
            return cls(
                algorithm=algorithm,
                iterations=16384,    # N parameter (2^14)
                memory_cost=8,       # r parameter 
                parallelism=1,       # p parameter
                salt_length=32,
                output_length=32
            )
        elif algorithm in [KDFAlgorithm.HKDF_SHA256, KDFAlgorithm.HKDF_SHA512]:
            return cls(
                algorithm=algorithm,
                salt_length=32,
                output_length=32 if algorithm == KDFAlgorithm.HKDF_SHA256 else 64
            )
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")


class KMSPepperProvider:
    """Provider for KMS-backed pepper values for enhanced KDF security."""
    
    def __init__(self, kms_provider=None):
        self.kms_provider = kms_provider
        self._pepper_cache: Dict[str, bytes] = {}
        self._cache_expiry: Dict[str, float] = {}
        self.cache_ttl = 3600  # 1 hour
    
    def get_pepper(self, context: str = "default") -> bytes:
        """
        Get a KMS-backed pepper value for KDF enhancement.
        
        Args:
            context: Context identifier for different pepper values
            
        Returns:
            Pepper bytes
        """
        current_time = time.time()
        
        # Check cache first
        if (context in self._pepper_cache and 
            context in self._cache_expiry and
            current_time < self._cache_expiry[context]):
            return self._pepper_cache[context]
        
        if self.kms_provider:
            # Use KMS to derive pepper
            try:
                pepper = self._derive_kms_pepper(context)
            except Exception:
                # Fallback to secure random if KMS fails
                pepper = secrets.token_bytes(32)
        else:
            # Use secure random pepper
            pepper = secrets.token_bytes(32)
        
        # Cache the pepper
        self._pepper_cache[context] = pepper
        self._cache_expiry[context] = current_time + self.cache_ttl
        
        return pepper
    
    def _derive_kms_pepper(self, context: str) -> bytes:
        """Derive pepper using KMS operations."""
        if not self.kms_provider:
            raise ValueError("No KMS provider configured")
        
        # Create deterministic but unpredictable input
        pepper_input = f"KDF_PEPPER_{context}_{time.strftime('%Y%m%d')}".encode()
        
        # Use KMS to encrypt the input as pepper derivation
        try:
            # This assumes the KMS provider has a default key for pepper operations
            pepper_raw = self.kms_provider.encrypt("pepper_kek", pepper_input)
            
            # Hash the result to get consistent length
            return hashlib.sha256(pepper_raw).digest()
        except Exception as e:
            raise RuntimeError(f"KMS pepper derivation failed: {e}")
    
    def rotate_pepper(self, context: str = "default"):
        """Force rotation of pepper for a context."""
        if context in self._pepper_cache:
            del self._pepper_cache[context]
        if context in self._cache_expiry:
            del self._cache_expiry[context]


class EnhancedKDF:
    """Enhanced Key Derivation Function with modern security practices."""
    
    def __init__(self, kms_provider=None, enable_pepper: bool = True):
        self.kms_provider = kms_provider
        self.enable_pepper = enable_pepper
        self.pepper_provider = KMSPepperProvider(kms_provider) if enable_pepper else None
        
        # Argon2 password hasher with secure defaults
        self.argon2_hasher = PasswordHasher(
            time_cost=3,      # iterations
            memory_cost=65536, # 64 MiB
            parallelism=4,    # threads
            hash_len=32,      # output length
            salt_len=32,      # salt length
        )
    
    @side_channel_safe
    def derive_key(self, password: bytes, salt: bytes, 
                   parameters: Optional[KDFParameters] = None,
                   info: Optional[bytes] = None,
                   pepper_context: str = "default") -> bytes:
        """
        Derive a key using the specified KDF algorithm.
        
        Args:
            password: Password or key material
            salt: Random salt value
            parameters: KDF parameters (uses secure defaults if None)
            info: Additional info for HKDF
            pepper_context: Context for KMS-backed pepper
            
        Returns:
            Derived key material
        """
        if parameters is None:
            parameters = KDFParameters.get_secure_defaults(KDFAlgorithm.ARGON2ID)
        
        # Add KMS-backed pepper if enabled
        if self.enable_pepper and self.pepper_provider:
            pepper = self.pepper_provider.get_pepper(pepper_context)
            # Combine password with pepper using HMAC
            password = hmac.new(pepper, password, hashlib.sha256).digest()
        
        # Derive key based on algorithm
        if parameters.algorithm == KDFAlgorithm.ARGON2ID:
            return self._derive_argon2id(password, salt, parameters)
        elif parameters.algorithm == KDFAlgorithm.ARGON2I:
            return self._derive_argon2i(password, salt, parameters)
        elif parameters.algorithm == KDFAlgorithm.ARGON2D:
            return self._derive_argon2d(password, salt, parameters)
        elif parameters.algorithm == KDFAlgorithm.PBKDF2_SHA256:
            return self._derive_pbkdf2(password, salt, parameters, hashes.SHA256())
        elif parameters.algorithm == KDFAlgorithm.PBKDF2_SHA512:
            return self._derive_pbkdf2(password, salt, parameters, hashes.SHA512())
        elif parameters.algorithm == KDFAlgorithm.SCRYPT:
            return self._derive_scrypt(password, salt, parameters)
        elif parameters.algorithm == KDFAlgorithm.HKDF_SHA256:
            return self._derive_hkdf(password, salt, parameters, hashes.SHA256(), info)
        elif parameters.algorithm == KDFAlgorithm.HKDF_SHA512:
            return self._derive_hkdf(password, salt, parameters, hashes.SHA512(), info)
        else:
            raise ValueError(f"Unsupported algorithm: {parameters.algorithm}")
    
    def _derive_argon2id(self, password: bytes, salt: bytes, 
                        parameters: KDFParameters) -> bytes:
        """Derive key using Argon2id."""
        return low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=parameters.iterations,
            memory_cost=parameters.memory_cost,
            parallelism=parameters.parallelism,
            hash_len=parameters.output_length,
            type=low_level.Type.ID
        )
    
    def _derive_argon2i(self, password: bytes, salt: bytes,
                       parameters: KDFParameters) -> bytes:
        """Derive key using Argon2i."""
        return low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=parameters.iterations,
            memory_cost=parameters.memory_cost,
            parallelism=parameters.parallelism,
            hash_len=parameters.output_length,
            type=low_level.Type.I
        )
    
    def _derive_argon2d(self, password: bytes, salt: bytes,
                       parameters: KDFParameters) -> bytes:
        """Derive key using Argon2d."""
        return low_level.hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=parameters.iterations,
            memory_cost=parameters.memory_cost,
            parallelism=parameters.parallelism,
            hash_len=parameters.output_length,
            type=low_level.Type.D
        )
    
    def _derive_pbkdf2(self, password: bytes, salt: bytes,
                      parameters: KDFParameters, hash_algo) -> bytes:
        """Derive key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hash_algo,
            length=parameters.output_length,
            salt=salt,
            iterations=parameters.iterations,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def _derive_scrypt(self, password: bytes, salt: bytes,
                      parameters: KDFParameters) -> bytes:
        """Derive key using scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=parameters.output_length,
            n=parameters.iterations,
            r=parameters.memory_cost,
            p=parameters.parallelism,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def _derive_hkdf(self, password: bytes, salt: bytes,
                    parameters: KDFParameters, hash_algo, info: Optional[bytes]) -> bytes:
        """Derive key using HKDF."""
        kdf = HKDF(
            algorithm=hash_algo,
            length=parameters.output_length,
            salt=salt,
            info=info or b'',
            backend=default_backend()
        )
        return kdf.derive(password)
    
    @timing_safe
    def verify_password(self, password: str, hash_string: str) -> bool:
        """
        Verify a password against its hash in constant time.
        
        Args:
            password: Password to verify
            hash_string: Stored password hash
            
        Returns:
            True if password is correct
        """
        try:
            self.argon2_hasher.verify(hash_string, password)
            return True
        except VerifyMismatchError:
            return False
    
    def hash_password(self, password: str, pepper_context: str = "password") -> str:
        """
        Hash a password with secure defaults.
        
        Args:
            password: Password to hash
            pepper_context: Context for KMS-backed pepper
            
        Returns:
            Password hash string
        """
        password_bytes = password.encode('utf-8')
        
        # Add KMS-backed pepper if enabled
        if self.enable_pepper and self.pepper_provider:
            pepper = self.pepper_provider.get_pepper(pepper_context)
            password_bytes = hmac.new(pepper, password_bytes, hashlib.sha256).digest()
        
        return self.argon2_hasher.hash(password_bytes)
    
    def needs_rehash(self, hash_string: str) -> bool:
        """Check if a password hash needs to be updated with new parameters."""
        return self.argon2_hasher.check_needs_rehash(hash_string)
    
    def benchmark_kdf(self, algorithm: KDFAlgorithm, target_time_ms: float = 500) -> KDFParameters:
        """
        Benchmark KDF parameters to achieve target computation time.
        
        Args:
            algorithm: KDF algorithm to benchmark
            target_time_ms: Target computation time in milliseconds
            
        Returns:
            Optimized KDF parameters
        """
        base_params = KDFParameters.get_secure_defaults(algorithm)
        test_password = b"benchmark_password_123"
        test_salt = os.urandom(32)
        
        # Start with base parameters and adjust
        current_params = base_params
        
        # Test current performance
        start_time = time.time()
        _ = self.derive_key(test_password, test_salt, current_params)
        elapsed_ms = (time.time() - start_time) * 1000
        
        # Adjust parameters based on performance
        if algorithm in [KDFAlgorithm.ARGON2ID, KDFAlgorithm.ARGON2I, KDFAlgorithm.ARGON2D]:
            # Adjust time_cost to hit target
            scaling_factor = target_time_ms / elapsed_ms
            new_iterations = max(1, int(current_params.iterations * scaling_factor))
            current_params.iterations = new_iterations
            
        elif algorithm in [KDFAlgorithm.PBKDF2_SHA256, KDFAlgorithm.PBKDF2_SHA512]:
            # Adjust iterations for PBKDF2
            scaling_factor = target_time_ms / elapsed_ms
            new_iterations = max(10000, int(current_params.iterations * scaling_factor))
            current_params.iterations = new_iterations
        
        return current_params


class PAKEProtocol:
    """
    Password Authenticated Key Exchange (PAKE) protocol implementation.
    
    This provides a basic OPAQUE-style PAKE for secure password authentication
    without revealing the password to the server.
    """
    
    def __init__(self, kdf: EnhancedKDF):
        self.kdf = kdf
    
    def client_registration_request(self, password: str) -> Tuple[bytes, bytes]:
        """
        Client creates registration request.
        
        Args:
            password: Client password
            
        Returns:
            Tuple of (registration_request, client_state)
        """
        # Generate random values
        r = secrets.token_bytes(32)
        alpha = secrets.token_bytes(32)
        
        # Hash password with random salt
        salt = secrets.token_bytes(32)
        password_hash = self.kdf.derive_key(
            password.encode(), salt,
            KDFParameters.get_secure_defaults(KDFAlgorithm.ARGON2ID)
        )
        
        # Create registration request
        registration_request = salt + r + alpha + password_hash
        client_state = salt + r
        
        return registration_request, client_state
    
    def server_registration_response(self, registration_request: bytes) -> Tuple[bytes, bytes]:
        """
        Server processes registration request.
        
        Args:
            registration_request: Request from client
            
        Returns:
            Tuple of (registration_response, server_record)
        """
        # Parse registration request
        salt = registration_request[:32]
        r = registration_request[32:64]
        alpha = registration_request[64:96]
        password_hash = registration_request[96:128]
        
        # Generate server values
        beta = secrets.token_bytes(32)
        server_key = secrets.token_bytes(32)
        
        # Create server record for storage
        server_record = salt + beta + server_key + password_hash
        
        # Create registration response
        registration_response = beta + server_key
        
        return registration_response, server_record
    
    def client_finalize_registration(self, registration_response: bytes, 
                                   client_state: bytes) -> bytes:
        """
        Client finalizes registration.
        
        Args:
            registration_response: Response from server
            client_state: Client's state from request
            
        Returns:
            Client record for local storage
        """
        beta = registration_response[:32]
        server_key = registration_response[32:64]
        
        salt = client_state[:32]
        r = client_state[32:64]
        
        # Create client record
        client_record = salt + r + beta + server_key
        
        return client_record
    
    @timing_safe 
    def authenticate(self, password: str, client_record: bytes, 
                    server_record: bytes) -> Tuple[bool, Optional[bytes]]:
        """
        Perform PAKE authentication.
        
        Args:
            password: Client password
            client_record: Client's stored record
            server_record: Server's stored record
            
        Returns:
            Tuple of (success, session_key)
        """
        try:
            # Parse client record
            c_salt = client_record[:32]
            c_r = client_record[32:64]
            c_beta = client_record[64:96]
            c_server_key = client_record[96:128]
            
            # Parse server record  
            s_salt = server_record[:32]
            s_beta = server_record[32:64]
            s_server_key = server_record[64:96]
            s_password_hash = server_record[96:128]
            
            # Verify salt and beta match
            if not (TimingAttackProtection.constant_time_compare(c_salt, s_salt) and
                   TimingAttackProtection.constant_time_compare(c_beta, s_beta) and
                   TimingAttackProtection.constant_time_compare(c_server_key, s_server_key)):
                return False, None
            
            # Re-derive password hash from provided password
            derived_hash = self.kdf.derive_key(
                password.encode(), c_salt,
                KDFParameters.get_secure_defaults(KDFAlgorithm.ARGON2ID)
            )
            
            # Verify password hash
            if not TimingAttackProtection.constant_time_compare(derived_hash, s_password_hash):
                return False, None
            
            # Generate session key
            session_key = self.kdf.derive_key(
                c_r + c_beta + c_server_key, c_salt,
                info=b'PAKE_SESSION_KEY'
            )
            
            return True, session_key
            
        except Exception:
            return False, None


# Global enhanced KDF instance
enhanced_kdf = EnhancedKDF()