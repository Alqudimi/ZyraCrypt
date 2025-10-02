"""
Homomorphic Encryption Implementation

This module implements the Paillier cryptosystem, which supports:
- Additive homomorphism: E(m1) + E(m2) = E(m1 + m2)
- Scalar multiplication: c * E(m) = E(c * m)

This enables computation on encrypted data without decryption, useful for:
- Privacy-preserving data analytics
- Secure voting systems
- Confidential financial calculations
- Federated learning
"""

import os
import secrets
import math
from typing import Tuple, Optional
from dataclasses import dataclass


def is_prime(n: int, k: int = 10) -> bool:
    """
    Miller-Rabin primality test.
    
    Args:
        n: Number to test
        k: Number of rounds (higher = more accurate)
        
    Returns:
        True if probably prime, False if definitely composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Miller-Rabin test
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a prime number of specified bit length.
    
    Args:
        bits: Bit length of prime
        
    Returns:
        A prime number
    """
    while True:
        # Generate random odd number of correct bit length
        candidate = secrets.randbits(bits) | (1 << bits - 1) | 1
        
        # Small prime check for efficiency
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
        if any(candidate % p == 0 and candidate != p for p in small_primes):
            continue
        
        # Miller-Rabin test
        if is_prime(candidate):
            return candidate


def gcd(a: int, b: int) -> int:
    """Greatest Common Divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """Least Common Multiple."""
    return abs(a * b) // gcd(a, b)


def mod_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse using Extended Euclidean Algorithm.
    
    Args:
        a: Number to invert
        m: Modulus
        
    Returns:
        Modular inverse of a mod m
    """
    if gcd(a, m) != 1:
        raise ValueError("Modular inverse does not exist")
    
    # Extended Euclidean Algorithm
    m0, x0, x1 = m, 0, 1
    
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    
    return x1 + m0 if x1 < 0 else x1


@dataclass
class PaillierPublicKey:
    """Paillier public key."""
    n: int  # Modulus n = p * q
    n_squared: int  # n^2
    g: int  # Generator g
    bits: int  # Key size in bits


@dataclass
class PaillierPrivateKey:
    """Paillier private key."""
    lambda_val: int  # λ = lcm(p-1, q-1)
    mu: int  # μ = (L(g^λ mod n²))^(-1) mod n
    
    def l_function(self, x: int, n: int) -> int:
        """L(x) = (x - 1) / n"""
        return (x - 1) // n


class PaillierCiphertext:
    """
    Encrypted value in Paillier cryptosystem.
    
    Supports homomorphic operations.
    """
    
    def __init__(self, ciphertext: int, public_key: PaillierPublicKey):
        """
        Initialize ciphertext.
        
        Args:
            ciphertext: Encrypted value
            public_key: Public key used for encryption
        """
        self.ciphertext = ciphertext
        self.public_key = public_key
    
    def __add__(self, other: 'PaillierCiphertext') -> 'PaillierCiphertext':
        """
        Homomorphic addition: E(m1) + E(m2) = E(m1 + m2)
        
        Args:
            other: Another ciphertext
            
        Returns:
            Ciphertext of sum
        """
        if self.public_key.n != other.public_key.n:
            raise ValueError("Ciphertexts from different keys")
        
        new_ciphertext = (self.ciphertext * other.ciphertext) % self.public_key.n_squared
        return PaillierCiphertext(new_ciphertext, self.public_key)
    
    def __mul__(self, scalar: int) -> 'PaillierCiphertext':
        """
        Scalar multiplication: c * E(m) = E(c * m)
        
        Args:
            scalar: Scalar value
            
        Returns:
            Ciphertext of scalar product
        """
        new_ciphertext = pow(self.ciphertext, scalar, self.public_key.n_squared)
        return PaillierCiphertext(new_ciphertext, self.public_key)
    
    def __rmul__(self, scalar: int) -> 'PaillierCiphertext':
        """Right multiplication."""
        return self.__mul__(scalar)
    
    def __sub__(self, other: 'PaillierCiphertext') -> 'PaillierCiphertext':
        """
        Homomorphic subtraction: E(m1) - E(m2) = E(m1 - m2)
        
        Args:
            other: Another ciphertext
            
        Returns:
            Ciphertext of difference
        """
        # E(m1 - m2) = E(m1) * E(-m2) = E(m1) * E(m2)^(-1)
        if self.public_key.n != other.public_key.n:
            raise ValueError("Ciphertexts from different keys")
        
        inv_other = mod_inverse(other.ciphertext, self.public_key.n_squared)
        new_ciphertext = (self.ciphertext * inv_other) % self.public_key.n_squared
        return PaillierCiphertext(new_ciphertext, self.public_key)


class HomomorphicEncryption:
    """
    Paillier Homomorphic Encryption System.
    
    Supports additive homomorphism and scalar multiplication on encrypted data.
    """
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize Paillier encryption system.
        
        Args:
            key_size: Key size in bits (default: 2048)
        """
        self.key_size = key_size
        self.public_key: Optional[PaillierPublicKey] = None
        self.private_key: Optional[PaillierPrivateKey] = None
    
    def generate_keypair(self) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
        """
        Generate Paillier public/private key pair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        # Generate two large primes p and q
        p = generate_prime(self.key_size // 2)
        q = generate_prime(self.key_size // 2)
        
        # Ensure p != q
        while p == q:
            q = generate_prime(self.key_size // 2)
        
        # Compute n = p * q
        n = p * q
        n_squared = n * n
        
        # Compute λ = lcm(p-1, q-1)
        lambda_val = lcm(p - 1, q - 1)
        
        # Choose g = n + 1 (standard choice for simplicity)
        g = n + 1
        
        # Compute μ = (L(g^λ mod n²))^(-1) mod n
        # where L(x) = (x - 1) / n
        g_lambda = pow(g, lambda_val, n_squared)
        l_value = (g_lambda - 1) // n
        mu = mod_inverse(l_value, n)
        
        # Create keys
        public_key = PaillierPublicKey(n=n, n_squared=n_squared, g=g, bits=self.key_size)
        private_key = PaillierPrivateKey(lambda_val=lambda_val, mu=mu)
        
        self.public_key = public_key
        self.private_key = private_key
        
        return public_key, private_key
    
    def encrypt_for_computation(self, data: int, public_key: Optional[PaillierPublicKey] = None) -> PaillierCiphertext:
        """
        Encrypt data for homomorphic computation.
        
        Args:
            data: Integer to encrypt
            public_key: Public key (uses stored key if None)
            
        Returns:
            Encrypted ciphertext
        """
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            raise ValueError("No public key available")
        
        # Ensure data is within valid range
        if data < 0 or data >= public_key.n:
            raise ValueError(f"Data must be in range [0, {public_key.n})")
        
        # Choose random r where 0 < r < n and gcd(r, n) = 1
        while True:
            r = secrets.randbelow(public_key.n - 1) + 1
            if gcd(r, public_key.n) == 1:
                break
        
        # c = g^m * r^n mod n²
        g_m = pow(public_key.g, data, public_key.n_squared)
        r_n = pow(r, public_key.n, public_key.n_squared)
        ciphertext = (g_m * r_n) % public_key.n_squared
        
        return PaillierCiphertext(ciphertext, public_key)
    
    def decrypt_computation_result(self, ciphertext: PaillierCiphertext, 
                                   private_key: Optional[PaillierPrivateKey] = None) -> int:
        """
        Decrypt result of homomorphic computation.
        
        Args:
            ciphertext: Encrypted ciphertext
            private_key: Private key (uses stored key if None)
            
        Returns:
            Decrypted integer
        """
        if private_key is None:
            private_key = self.private_key
        
        if private_key is None:
            raise ValueError("No private key available")
        
        public_key = ciphertext.public_key
        
        # m = L(c^λ mod n²) * μ mod n
        c_lambda = pow(ciphertext.ciphertext, private_key.lambda_val, public_key.n_squared)
        l_value = (c_lambda - 1) // public_key.n
        plaintext = (l_value * private_key.mu) % public_key.n
        
        return plaintext
    
    def add_encrypted(self, ciphertext1: PaillierCiphertext, 
                     ciphertext2: PaillierCiphertext) -> PaillierCiphertext:
        """
        Add two encrypted numbers without decrypting them.
        
        Args:
            ciphertext1: First encrypted number
            ciphertext2: Second encrypted number
            
        Returns:
            Encrypted sum
        """
        return ciphertext1 + ciphertext2
    
    def multiply_encrypted(self, ciphertext: PaillierCiphertext, 
                          scalar: int) -> PaillierCiphertext:
        """
        Multiply encrypted number by plaintext scalar.
        
        Args:
            ciphertext: Encrypted number
            scalar: Plaintext scalar
            
        Returns:
            Encrypted product
        """
        return ciphertext * scalar
    
    def subtract_encrypted(self, ciphertext1: PaillierCiphertext,
                          ciphertext2: PaillierCiphertext) -> PaillierCiphertext:
        """
        Subtract two encrypted numbers without decrypting them.
        
        Args:
            ciphertext1: First encrypted number
            ciphertext2: Second encrypted number
            
        Returns:
            Encrypted difference
        """
        return ciphertext1 - ciphertext2


# Convenience functions
def create_homomorphic_system(key_size: int = 2048) -> HomomorphicEncryption:
    """
    Create and initialize a homomorphic encryption system.
    
    Args:
        key_size: Key size in bits (default: 2048)
        
    Returns:
        Initialized HomomorphicEncryption instance with generated keys
    """
    he = HomomorphicEncryption(key_size)
    he.generate_keypair()
    return he


class SecureVotingSystem:
    """
    Example: Secure voting system using homomorphic encryption.
    
    Votes are encrypted, tallied in encrypted form, then decrypted for final count.
    """
    
    def __init__(self, key_size: int = 1024):
        """Initialize voting system with smaller key for performance."""
        self.he = HomomorphicEncryption(key_size)
        self.public_key, self.private_key = self.he.generate_keypair()
        self.encrypted_votes = []
    
    def cast_vote(self, vote: int):
        """
        Cast an encrypted vote.
        
        Args:
            vote: Vote value (e.g., 0 or 1 for yes/no)
        """
        encrypted_vote = self.he.encrypt_for_computation(vote, self.public_key)
        self.encrypted_votes.append(encrypted_vote)
    
    def tally_votes(self) -> int:
        """
        Tally all votes without decrypting individual votes.
        
        Returns:
            Total vote count
        """
        if not self.encrypted_votes:
            return 0
        
        # Sum all encrypted votes
        total = self.encrypted_votes[0]
        for vote in self.encrypted_votes[1:]:
            total = total + vote
        
        # Decrypt final tally
        result = self.he.decrypt_computation_result(total, self.private_key)
        return result
    
    def get_vote_count(self) -> int:
        """Get number of votes cast."""
        return len(self.encrypted_votes)


class PrivateDataAnalytics:
    """
    Example: Privacy-preserving data analytics using homomorphic encryption.
    
    Allows computing statistics on encrypted data.
    """
    
    def __init__(self, key_size: int = 1024):
        """Initialize analytics system."""
        self.he = HomomorphicEncryption(key_size)
        self.public_key, self.private_key = self.he.generate_keypair()
    
    def compute_encrypted_sum(self, values: list[int]) -> int:
        """
        Compute sum of encrypted values.
        
        Args:
            values: List of integers
            
        Returns:
            Sum of values
        """
        # Encrypt all values
        encrypted_values = [
            self.he.encrypt_for_computation(val, self.public_key) 
            for val in values
        ]
        
        # Sum in encrypted form
        total = encrypted_values[0]
        for enc_val in encrypted_values[1:]:
            total = total + enc_val
        
        # Decrypt result
        return self.he.decrypt_computation_result(total, self.private_key)
    
    def compute_encrypted_average(self, values: list[int]) -> float:
        """
        Compute average of encrypted values.
        
        Args:
            values: List of integers
            
        Returns:
            Average of values
        """
        total = self.compute_encrypted_sum(values)
        return total / len(values) if values else 0.0
    
    def compute_weighted_sum(self, values: list[int], weights: list[int]) -> int:
        """
        Compute weighted sum: sum(value[i] * weight[i])
        
        Args:
            values: List of values
            weights: List of weights
            
        Returns:
            Weighted sum
        """
        if len(values) != len(weights):
            raise ValueError("Values and weights must have same length")
        
        # Encrypt values
        encrypted_values = [
            self.he.encrypt_for_computation(val, self.public_key)
            for val in values
        ]
        
        # Multiply by weights (scalar multiplication)
        weighted = [enc_val * weight for enc_val, weight in zip(encrypted_values, weights)]
        
        # Sum weighted values
        total = weighted[0]
        for w in weighted[1:]:
            total = total + w
        
        # Decrypt result
        return self.he.decrypt_computation_result(total, self.private_key)
