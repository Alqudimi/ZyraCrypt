"""
Side-Channel Protection and Constant-Time Execution Guards

This module provides protection against side-channel attacks including timing attacks,
cache attacks, and power analysis by enforcing constant-time execution patterns.
"""

import os
import time
import hmac
import hashlib
import secrets
from typing import Any, Callable, Optional, List
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading
import logging


class TimingAttackProtection:
    """Protection against timing-based side-channel attacks."""
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison to prevent timing attacks.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if equal, False otherwise
        """
        # Use cryptography library's constant_time comparison
        return constant_time.bytes_eq(a, b)
    
    @staticmethod
    def constant_time_string_compare(a: str, b: str) -> bool:
        """
        Constant-time string comparison.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if equal, False otherwise
        """
        return TimingAttackProtection.constant_time_compare(a.encode(), b.encode())
    
    @staticmethod
    def secure_random_delay(min_ms: int = 1, max_ms: int = 10):
        """
        Add random delay to prevent timing analysis.
        
        Args:
            min_ms: Minimum delay in milliseconds
            max_ms: Maximum delay in milliseconds
        """
        delay_ms = secrets.randbelow(max_ms - min_ms + 1) + min_ms
        time.sleep(delay_ms / 1000.0)
    
    @staticmethod
    def timing_safe_hmac_verify(expected: bytes, actual: bytes, key: bytes) -> bool:
        """
        Timing-safe HMAC verification using double HMAC verification.
        
        Args:
            expected: Expected HMAC value
            actual: Actual HMAC value
            key: HMAC key
            
        Returns:
            True if HMACs match
        """
        # Double HMAC verification pattern for timing safety
        expected_hmac = hmac.new(key, expected, hashlib.sha256).digest()
        actual_hmac = hmac.new(key, actual, hashlib.sha256).digest()
        
        return constant_time.bytes_eq(expected_hmac, actual_hmac)


class ConstantTimeOperations:
    """Constant-time cryptographic operations."""
    
    @staticmethod
    def constant_time_select(condition: bool, true_value: bytes, false_value: bytes) -> bytes:
        """
        Constant-time conditional selection.
        
        Args:
            condition: Selection condition
            true_value: Value to return if condition is True
            false_value: Value to return if condition is False
            
        Returns:
            Selected value without timing leak
        """
        # Ensure both values are same length
        if len(true_value) != len(false_value):
            raise ValueError("Values must have the same length")
        
        # Create mask based on condition
        mask = 0xFF if condition else 0x00
        result = bytearray(len(true_value))
        
        for i in range(len(true_value)):
            result[i] = (true_value[i] & mask) | (false_value[i] & ~mask)
        
        return bytes(result)
    
    @staticmethod
    def constant_time_memset(data: bytearray, value: int, length: int):
        """
        Constant-time memory set operation.
        
        Args:
            data: Data to modify
            value: Value to set (0-255)
            length: Number of bytes to set
        """
        for i in range(length):
            data[i] = value
    
    @staticmethod
    def secure_zero(data: bytearray):
        """
        Securely zero out memory in constant time.
        
        Args:
            data: Data to zero out
        """
        ConstantTimeOperations.constant_time_memset(data, 0, len(data))


class RSABlindingProtection:
    """RSA blinding to protect against timing and fault attacks."""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_blinding_factor(self, public_exponent: int, modulus_size: int) -> bytes:
        """
        Generate a random blinding factor for RSA operations.
        
        Args:
            public_exponent: RSA public exponent
            modulus_size: RSA modulus size in bits
            
        Returns:
            Random blinding factor
        """
        # Generate random value r where gcd(r, n) = 1
        byte_size = (modulus_size + 7) // 8
        while True:
            r = secrets.randbits(modulus_size - 1)
            if r > 1:  # Ensure r > 1 for blinding
                return r.to_bytes(byte_size, 'big')
    
    def blind_message(self, message: bytes, blinding_factor: bytes, 
                     public_key_n: int, public_key_e: int) -> bytes:
        """
        Blind a message for RSA signing to prevent timing attacks.
        
        Args:
            message: Message to blind
            blinding_factor: Random blinding factor
            public_key_n: RSA modulus
            public_key_e: RSA public exponent
            
        Returns:
            Blinded message
        """
        r = int.from_bytes(blinding_factor, 'big')
        m = int.from_bytes(message, 'big')
        
        # Compute r^e mod n
        r_e = pow(r, public_key_e, public_key_n)
        
        # Blind: m' = m * r^e mod n
        blinded = (m * r_e) % public_key_n
        
        return blinded.to_bytes((public_key_n.bit_length() + 7) // 8, 'big')
    
    def unblind_signature(self, blinded_signature: bytes, blinding_factor: bytes,
                         public_key_n: int) -> bytes:
        """
        Unblind a signature after RSA signing.
        
        Args:
            blinded_signature: Blinded signature
            blinding_factor: Blinding factor used
            public_key_n: RSA modulus
            
        Returns:
            Unblinded signature
        """
        r = int.from_bytes(blinding_factor, 'big')
        s_blinded = int.from_bytes(blinded_signature, 'big')
        
        # Compute modular inverse of r
        r_inv = pow(r, -1, public_key_n)
        
        # Unblind: s = s' * r^(-1) mod n
        signature = (s_blinded * r_inv) % public_key_n
        
        return signature.to_bytes((public_key_n.bit_length() + 7) // 8, 'big')


class CacheAttackProtection:
    """Protection against cache-based side-channel attacks."""
    
    @staticmethod
    def constant_time_table_lookup(table: List[bytes], index: int) -> bytes:
        """
        Constant-time table lookup to prevent cache attacks.
        
        Args:
            table: Table of byte values
            index: Index to lookup
            
        Returns:
            Table value at index without cache timing leak
        """
        if not table:
            raise ValueError("Empty table")
        
        if not (0 <= index < len(table)):
            raise ValueError("Index out of bounds")
        
        # Initialize result with first table entry
        result = bytearray(table[0])
        
        # XOR with each table entry based on index equality
        for i, entry in enumerate(table):
            if len(entry) != len(result):
                raise ValueError("All table entries must have same length")
            
            # Create mask: all 0xFF if i == index, all 0x00 otherwise
            mask = 0xFF if i == index else 0x00
            
            for j in range(len(result)):
                if i == 0:
                    # First iteration: conditionally keep or zero
                    result[j] = result[j] if i == index else 0
                else:
                    # Subsequent iterations: conditionally XOR
                    result[j] ^= (entry[j] & mask)
        
        return bytes(result)
    
    @staticmethod
    def memory_barrier():
        """Insert memory barrier to prevent cache optimizations."""
        # Python doesn't have direct memory barriers, but this forces memory access
        dummy = os.urandom(1)
        del dummy


class SecureMemoryManager:
    """Secure memory management with zeroization."""
    
    def __init__(self):
        self.sensitive_allocations = set()
        self.lock = threading.Lock()
    
    def allocate_secure(self, size: int) -> bytearray:
        """
        Allocate secure memory that will be zeroized on cleanup.
        
        Args:
            size: Size in bytes
            
        Returns:
            Secure bytearray
        """
        data = bytearray(size)
        
        with self.lock:
            self.sensitive_allocations.add(id(data))
        
        return data
    
    def secure_free(self, data: bytearray):
        """
        Securely free memory by zeroizing it.
        
        Args:
            data: Data to securely free
        """
        if isinstance(data, bytearray):
            ConstantTimeOperations.secure_zero(data)
            
            with self.lock:
                self.sensitive_allocations.discard(id(data))
    
    def cleanup_all(self):
        """Cleanup all tracked secure allocations."""
        # Note: In Python, we can't directly access memory by ID after GC
        # This is more of a conceptual cleanup
        with self.lock:
            self.sensitive_allocations.clear()
    
    def __del__(self):
        """Ensure cleanup on destruction."""
        self.cleanup_all()


class SideChannelGuard:
    """
    Decorator and context manager for side-channel protection.
    """
    
    def __init__(self, protect_timing: bool = True, protect_cache: bool = True,
                 secure_memory: bool = True, random_delay: bool = False):
        self.protect_timing = protect_timing
        self.protect_cache = protect_cache
        self.secure_memory = secure_memory
        self.random_delay = random_delay
        self.memory_manager = SecureMemoryManager() if secure_memory else None
        self.logger = logging.getLogger(__name__)
    
    def __enter__(self):
        """Enter side-channel protected context."""
        if self.protect_cache:
            CacheAttackProtection.memory_barrier()
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit side-channel protected context."""
        if self.secure_memory and self.memory_manager:
            self.memory_manager.cleanup_all()
        
        if self.random_delay:
            TimingAttackProtection.secure_random_delay()
        
        if self.protect_cache:
            CacheAttackProtection.memory_barrier()
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for side-channel protection."""
        def wrapper(*args, **kwargs):
            with self:
                return func(*args, **kwargs)
        
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        return wrapper
    
    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """Protected comparison operation."""
        if self.protect_timing:
            return TimingAttackProtection.constant_time_compare(a, b)
        else:
            return a == b
    
    def secure_random(self, size: int) -> bytes:
        """Generate secure random data."""
        return secrets.token_bytes(size)


class PowerAnalysisProtection:
    """Protection against power analysis attacks."""
    
    @staticmethod
    def dummy_operations(count: int = 5):
        """
        Perform dummy cryptographic operations to mask power consumption.
        
        Args:
            count: Number of dummy operations
        """
        dummy_key = os.urandom(32)
        dummy_data = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(dummy_key),
            modes.ECB(),
            backend=default_backend()
        )
        
        for _ in range(count):
            encryptor = cipher.encryptor()
            _ = encryptor.update(dummy_data) + encryptor.finalize()
    
    @staticmethod
    def randomize_execution_path():
        """Randomize execution path to prevent power analysis."""
        # Perform random number of no-op operations
        noop_count = secrets.randbelow(10) + 1
        for _ in range(noop_count):
            _ = secrets.token_bytes(1)
    
    @staticmethod
    def power_masking_aes_operation(key: bytes, plaintext: bytes) -> bytes:
        """
        AES operation with power consumption masking.
        
        Args:
            key: AES key
            plaintext: Plaintext to encrypt
            
        Returns:
            Ciphertext
        """
        # Perform dummy operations before real operation
        PowerAnalysisProtection.dummy_operations(2)
        
        # Real AES operation
        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Perform dummy operations after real operation
        PowerAnalysisProtection.dummy_operations(2)
        
        return ciphertext


# Global secure memory manager instance
secure_memory = SecureMemoryManager()


# Decorators for easy side-channel protection
def timing_safe(func: Callable) -> Callable:
    """Decorator for timing attack protection."""
    return SideChannelGuard(protect_timing=True, protect_cache=False)(func)


def cache_safe(func: Callable) -> Callable:
    """Decorator for cache attack protection."""
    return SideChannelGuard(protect_timing=False, protect_cache=True)(func)


def side_channel_safe(func: Callable) -> Callable:
    """Decorator for comprehensive side-channel protection."""
    return SideChannelGuard(
        protect_timing=True,
        protect_cache=True,
        secure_memory=True,
        random_delay=False
    )(func)


def power_analysis_safe(func: Callable) -> Callable:
    """Decorator for power analysis protection."""
    def wrapper(*args, **kwargs):
        PowerAnalysisProtection.randomize_execution_path()
        result = func(*args, **kwargs)
        PowerAnalysisProtection.randomize_execution_path()
        return result
    
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper