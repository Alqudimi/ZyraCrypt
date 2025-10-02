"""
Specialized Security Package
============================

Provides specialized security features including:
- File encryption and decryption
- Secure file deletion
- Secure session management
- Steganography (data hiding in images)
"""

from .file_encryption_manager import FileEncryptionManager
from .secure_deletion_unit import SecureDeletionUnit
from .secure_session_manager import SecureSessionManager
from .steganography_unit import SteganographyUnit

__all__ = [
    "FileEncryptionManager",
    "SecureDeletionUnit",
    "SecureSessionManager",
    "SteganographyUnit",
]
