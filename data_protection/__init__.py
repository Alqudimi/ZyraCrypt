"""
Data Protection Package
======================

Provides data protection utilities including:
- Data compression and decompression
- Data obfuscation and anonymization
- Secure memory handling and zeroing
- Data type-specific protection strategies
"""

from .data_protection_manager import DataProtectionManager
from .secure_memory_handling import SecureMemoryHandling
from .compression_unit import CompressionUnit
from .data_obfuscation_unit import DataObfuscationUnit

__all__ = [
    "DataProtectionManager",
    "SecureMemoryHandling",
    "CompressionUnit",
    "DataObfuscationUnit",
]
