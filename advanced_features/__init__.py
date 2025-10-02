"""
Advanced Features Module
========================

Provides advanced cryptographic features including:
- Threshold signatures and multi-signature schemes
- Multi-party computation (MPC)
- Secure enclaves (software and hardware-backed)
- Side-channel resistance
- White-box cryptography
- Homomorphic encryption
- Group end-to-end encryption
- Identity-based encryption (IBE)
- Blockchain cryptography functions
"""

from .threshold_multisig_enhanced import ThresholdECDSA, MultisigManager, ShamirSecretSharing
from .side_channel_protection import (
    SideChannelGuard,
    TimingAttackProtection,
    ConstantTimeOperations,
    SecureMemoryManager
)
from .security_hardening import SecurityHardeningManager

__all__ = [
    "ThresholdECDSA",
    "MultisigManager",
    "ShamirSecretSharing",
    "SideChannelGuard",
    "TimingAttackProtection",
    "ConstantTimeOperations",
    "SecureMemoryManager",
    "SecurityHardeningManager",
]
