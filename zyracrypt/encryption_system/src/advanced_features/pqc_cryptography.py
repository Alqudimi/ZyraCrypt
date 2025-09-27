"""
Post-Quantum Cryptography (PQC) Module

This module provides post-quantum cryptographic algorithms for key encapsulation
and digital signatures, offering protection against quantum computer attacks.
"""

import oqs
from typing import Tuple, Optional
import os


class PQCKeyEncapsulation:
    """
    Post-Quantum Key Encapsulation Mechanism (KEM) using ML-KEM (Kyber).
    """
    
    def __init__(self, algorithm: str = "Kyber512"):
        """
        Initialize the PQC KEM with the specified algorithm.
        
        Args:
            algorithm: The KEM algorithm to use (Kyber512, Kyber768, Kyber1024)
        """
        self.algorithm = algorithm
        self.kem = oqs.KeyEncapsulation(algorithm)
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new key pair for the KEM.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        public_key = self.kem.generate_keypair()
        private_key = self.kem.export_secret_key()
        return public_key, private_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        ciphertext, shared_secret = self.kem.encap_secret(public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret using the private key and ciphertext.
        
        Args:
            private_key: The private key for decapsulation
            ciphertext: The encapsulated ciphertext
            
        Returns:
            The shared secret
        """
        # Create a new KEM instance and load the private key
        kem = oqs.KeyEncapsulation(self.algorithm)
        kem.load_secret_key(private_key)
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret


class PQCDigitalSignature:
    """
    Post-Quantum Digital Signature using ML-DSA (Dilithium).
    """
    
    def __init__(self, algorithm: str = "Dilithium2"):
        """
        Initialize the PQC digital signature with the specified algorithm.
        
        Args:
            algorithm: The signature algorithm to use (Dilithium2, Dilithium3, Dilithium5)
        """
        self.algorithm = algorithm
        self.sig = oqs.Signature(algorithm)
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new key pair for digital signatures.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        public_key = self.sig.generate_keypair()
        private_key = self.sig.export_secret_key()
        return public_key, private_key
    
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Sign a message using the private key.
        
        Args:
            private_key: The private key for signing
            message: The message to sign
            
        Returns:
            The digital signature
        """
        # Create a new signature instance and load the private key
        sig = oqs.Signature(self.algorithm)
        sig.load_secret_key(private_key)
        signature = sig.sign(message)
        return signature
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a digital signature using the public key.
        
        Args:
            public_key: The public key for verification
            message: The original message
            signature: The digital signature to verify
            
        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            # Create a new signature instance
            sig = oqs.Signature(self.algorithm)
            return sig.verify(message, signature, public_key)
        except Exception:
            return False


class PQCHybridEncryption:
    """
    Hybrid encryption combining PQC KEM with symmetric encryption.
    """
    
    def __init__(self, kem_algorithm: str = "Kyber512"):
        """
        Initialize hybrid encryption with specified KEM algorithm.
        
        Args:
            kem_algorithm: The KEM algorithm to use for key encapsulation
        """
        self.kem = PQCKeyEncapsulation(kem_algorithm)
    
    def encrypt_hybrid(self, public_key: bytes, plaintext: bytes, 
                      symmetric_cipher=None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using hybrid PQC encryption.
        
        Args:
            public_key: Recipient's PQC public key
            plaintext: Data to encrypt
            symmetric_cipher: Symmetric encryption function (optional)
            
        Returns:
            Tuple of (encapsulated_key, encrypted_data)
        """
        # Encapsulate a shared secret
        ciphertext, shared_secret = self.kem.encapsulate(public_key)
        
        # Use the shared secret as a symmetric key
        if symmetric_cipher is None:
            # Simple XOR for demonstration (use proper AES-GCM in production)
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Derive a 256-bit key from shared secret
            key = shared_secret[:32] if len(shared_secret) >= 32 else shared_secret.ljust(32, b'\x00')
            iv = os.urandom(12)  # GCM IV
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag
            
            # Combine IV, tag, and encrypted data
            combined_data = iv + tag + encrypted_data
        else:
            combined_data = symmetric_cipher(shared_secret, plaintext)
        
        return ciphertext, combined_data
    
    def decrypt_hybrid(self, private_key: bytes, encapsulated_key: bytes, 
                      encrypted_data: bytes, symmetric_decipher=None) -> bytes:
        """
        Decrypt data using hybrid PQC decryption.
        
        Args:
            private_key: Recipient's PQC private key
            encapsulated_key: The encapsulated symmetric key
            encrypted_data: The encrypted data
            symmetric_decipher: Symmetric decryption function (optional)
            
        Returns:
            The decrypted plaintext
        """
        # Decapsulate the shared secret
        shared_secret = self.kem.decapsulate(private_key, encapsulated_key)
        
        # Decrypt using the shared secret
        if symmetric_decipher is None:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            
            # Derive the same key
            key = shared_secret[:32] if len(shared_secret) >= 32 else shared_secret.ljust(32, b'\x00')
            
            # Extract IV, tag, and ciphertext
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            plaintext = symmetric_decipher(shared_secret, encrypted_data)
        
        return plaintext


# Utility functions for algorithm selection
def get_available_kem_algorithms() -> list:
    """Get list of available KEM algorithms."""
    return oqs.get_enabled_KEM_mechanisms()


def get_available_signature_algorithms() -> list:
    """Get list of available signature algorithms."""
    return oqs.get_enabled_sig_mechanisms()


def select_pqc_algorithm(security_level: str = "medium") -> Tuple[str, str]:
    """
    Select appropriate PQC algorithms based on security level.
    
    Args:
        security_level: "low", "medium", or "high"
        
    Returns:
        Tuple of (kem_algorithm, signature_algorithm)
    """
    if security_level == "high":
        return "Kyber1024", "Dilithium5"
    elif security_level == "medium":
        return "Kyber768", "Dilithium3"
    else:  # low
        return "Kyber512", "Dilithium2"

