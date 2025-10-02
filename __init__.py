"""
ZyraCrypt - Enterprise-Grade Cryptographic Library
==================================================

A comprehensive cryptographic library providing advanced encryption services including:
- Symmetric and Asymmetric Encryption
- Post-Quantum Cryptography (PQC)
- Key Management and Key Derivation
- Threshold Signatures and Multi-Party Computation
- Secure Enclaves and Memory Protection
- Steganography and Data Obfuscation
- Blockchain Cryptography Functions

Example usage:
    >>> from zyracrypt import EncryptionFramework
    >>> framework = EncryptionFramework()
    >>> key = b"your-32-byte-key-here-for-aes256"
    >>> data = b"Sensitive information"
    >>> algo, iv, ciphertext, tag = framework.encrypt(data, key, "AES-GCM")
    >>> decrypted = framework.decrypt(algo, key, iv, ciphertext, tag)

For more information, see: https://github.com/AlqudimiSystems/zyracrypt
"""

__version__ = "2.0.0"
__author__ = "Alqudimi Systems"
__license__ = "MIT"

# Core Cryptography
from core_cryptography.encryption_framework import EncryptionFramework
from core_cryptography.symmetric_encryption import SymmetricEncryption
from core_cryptography.asymmetric_encryption import AsymmetricEncryption
from core_cryptography.algorithm_manager import AlgorithmManager

# Key Management
from key_management.key_manager import KeyManager
from key_management.key_generator import KeyGenerator
from key_management.secure_key_store import SecureKeyStore

# Data Protection
from data_protection.data_protection_manager import DataProtectionManager
from data_protection.secure_memory_handling import SecureMemoryHandling

# Make commonly used classes easily accessible
__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__license__",
    
    # Core Cryptography
    "EncryptionFramework",
    "SymmetricEncryption",
    "AsymmetricEncryption",
    "AlgorithmManager",
    
    # Key Management
    "KeyManager",
    "KeyGenerator",
    "SecureKeyStore",
    
    # Data Protection
    "DataProtectionManager",
    "SecureMemoryHandling",
]
