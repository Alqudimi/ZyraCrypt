"""
Post-Quantum Cryptography Package
=================================

Provides post-quantum cryptographic algorithms resistant to quantum attacks:
- Kyber (Key Encapsulation Mechanism)
- Dilithium (Digital Signatures)
- Hybrid encryption schemes (classical + post-quantum)

Note: Requires liboqs-python to be installed.
Install with: pip install zyracrypt[pqc]
"""

try:
    from .post_quantum_cryptography_unit import PostQuantumCryptographyUnit
    __all__ = ["PostQuantumCryptographyUnit"]
    _PQC_AVAILABLE = True
except ImportError:
    _PQC_AVAILABLE = False
    __all__ = []

def is_pqc_available() -> bool:
    """Check if post-quantum cryptography is available."""
    return _PQC_AVAILABLE
