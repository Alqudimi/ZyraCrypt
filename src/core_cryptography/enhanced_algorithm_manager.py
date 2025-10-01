"""
Enhanced Algorithm Manager

This module provides intelligent algorithm selection and orchestration for
various cryptographic operations, including traditional, post-quantum, and
advanced cryptographic techniques.
"""

from typing import Dict, List, Optional, Tuple, Any, Literal
import time
import logging
import os
from enum import Enum

# Import existing modules
from .symmetric_encryption import SymmetricEncryption
from .asymmetric_encryption import AsymmetricEncryption
try:
    from advanced_features.pqc_cryptography import (
        PQCKeyEncapsulation, PQCDigitalSignature, PQCHybridEncryption,
        select_pqc_algorithm
    )
    from advanced_features.ibe_cryptography import IBEKeyManager
    from key_management.enhanced_key_manager import EnhancedKeyManager
    ADVANCED_FEATURES_AVAILABLE = True
except ImportError:
    # Gracefully handle missing advanced features
    ADVANCED_FEATURES_AVAILABLE = False
    PQCKeyEncapsulation = None
    PQCDigitalSignature = None
    PQCHybridEncryption = None
    IBEKeyManager = None
    EnhancedKeyManager = None


class SecurityLevel(Enum):
    """Security levels for algorithm selection."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    QUANTUM_RESISTANT = "quantum_resistant"


class CryptographicPurpose(Enum):
    """Purposes for cryptographic operations."""
    DATA_ENCRYPTION = "data_encryption"
    KEY_EXCHANGE = "key_exchange"
    DIGITAL_SIGNATURE = "digital_signature"
    AUTHENTICATION = "authentication"
    PRIVACY_PRESERVING = "privacy_preserving"


class AlgorithmRecommendation:
    """Recommendation for cryptographic algorithm selection."""
    
    def __init__(self, algorithm: str, key_size: int, rationale: str, 
                 performance_score: float, security_score: float):
        self.algorithm = algorithm
        self.key_size = key_size
        self.rationale = rationale
        self.performance_score = performance_score  # 0-10 scale
        self.security_score = security_score  # 0-10 scale
        self.overall_score = (performance_score + security_score) / 2


class EnhancedAlgorithmManager:
    """Enhanced algorithm manager with intelligent selection capabilities."""
    
    def __init__(self, key_manager: Optional[EnhancedKeyManager] = None,
                 ibe_manager: Optional[IBEKeyManager] = None):
        self.key_manager = key_manager
        self.ibe_manager = ibe_manager
        
        # Initialize cryptographic modules
        self.symmetric = SymmetricEncryption()
        self.asymmetric = AsymmetricEncryption()
        
        # Initialize advanced features if available
        if ADVANCED_FEATURES_AVAILABLE:
            self.pqc_kem = PQCKeyEncapsulation()
            self.pqc_sig = PQCDigitalSignature()
            self.pqc_hybrid = PQCHybridEncryption()
        else:
            self.pqc_kem = None
            self.pqc_sig = None
            self.pqc_hybrid = None
        
        # Algorithm performance characteristics (estimated)
        self.algorithm_performance = {
            'AES-GCM': {'speed': 9, 'security': 8, 'quantum_resistant': False},
            'ChaCha20-Poly1305': {'speed': 8, 'security': 8, 'quantum_resistant': False},
            'RSA': {'speed': 4, 'security': 7, 'quantum_resistant': False},
            'ECC': {'speed': 7, 'security': 8, 'quantum_resistant': False},
            'Kyber512': {'speed': 6, 'security': 8, 'quantum_resistant': True},
            'Kyber768': {'speed': 5, 'security': 9, 'quantum_resistant': True},
            'Kyber1024': {'speed': 4, 'security': 10, 'quantum_resistant': True},
            'Dilithium2': {'speed': 5, 'security': 8, 'quantum_resistant': True},
            'Dilithium3': {'speed': 4, 'security': 9, 'quantum_resistant': True},
            'Dilithium5': {'speed': 3, 'security': 10, 'quantum_resistant': True},
        }
        
        self.logger = logging.getLogger(__name__)
    
    def recommend_algorithm(self, purpose: CryptographicPurpose, 
                          security_level: SecurityLevel,
                          data_size: Optional[int] = None,
                          performance_priority: bool = False) -> AlgorithmRecommendation:
        """
        Recommend the best algorithm for a specific use case.
        
        Args:
            purpose: The cryptographic purpose
            security_level: Required security level
            data_size: Size of data to be processed (if applicable)
            performance_priority: Whether to prioritize performance over security
            
        Returns:
            Algorithm recommendation with rationale
        """
        candidates = []
        
        if purpose == CryptographicPurpose.DATA_ENCRYPTION:
            candidates = self._get_encryption_candidates(security_level, data_size)
        elif purpose == CryptographicPurpose.KEY_EXCHANGE:
            candidates = self._get_key_exchange_candidates(security_level)
        elif purpose == CryptographicPurpose.DIGITAL_SIGNATURE:
            candidates = self._get_signature_candidates(security_level)
        
        # Score and rank candidates
        scored_candidates = []
        for algorithm, key_size in candidates:
            perf_score = self.algorithm_performance[algorithm]['speed']
            sec_score = self.algorithm_performance[algorithm]['security']
            
            # Adjust scores based on requirements
            if security_level == SecurityLevel.QUANTUM_RESISTANT:
                if not self.algorithm_performance[algorithm]['quantum_resistant']:
                    sec_score = max(0, sec_score - 5)  # Penalize non-QR algorithms
            
            if performance_priority:
                overall_score = perf_score * 0.7 + sec_score * 0.3
            else:
                overall_score = perf_score * 0.3 + sec_score * 0.7
            
            rationale = self._generate_rationale(algorithm, purpose, security_level, 
                                               performance_priority)
            
            recommendation = AlgorithmRecommendation(
                algorithm, key_size, rationale, perf_score, sec_score
            )
            recommendation.overall_score = overall_score
            scored_candidates.append(recommendation)
        
        # Return best candidate
        return max(scored_candidates, key=lambda x: x.overall_score)
    
    def _get_encryption_candidates(self, security_level: SecurityLevel, 
                                 data_size: Optional[int]) -> List[Tuple[str, int]]:
        """Get candidates for data encryption."""
        candidates = []
        
        if security_level == SecurityLevel.QUANTUM_RESISTANT:
            # For quantum resistance, use hybrid encryption with PQC
            candidates.extend([
                ('Kyber512', 512),
                ('Kyber768', 768),
                ('Kyber1024', 1024)
            ])
        else:
            # Traditional symmetric encryption
            candidates.extend([
                ('AES-GCM', 256),
                ('ChaCha20-Poly1305', 256)
            ])
            
            if security_level == SecurityLevel.HIGH:
                candidates.append(('AES-GCM', 256))  # Prefer AES for high security
        
        return candidates
    
    def _get_key_exchange_candidates(self, security_level: SecurityLevel) -> List[Tuple[str, int]]:
        """Get candidates for key exchange."""
        candidates = []
        
        if security_level == SecurityLevel.QUANTUM_RESISTANT:
            candidates.extend([
                ('Kyber512', 512),
                ('Kyber768', 768),
                ('Kyber1024', 1024)
            ])
        else:
            candidates.extend([
                ('ECC', 256),
                ('RSA', 2048),
                ('RSA', 3072)
            ])
        
        return candidates
    
    def _get_signature_candidates(self, security_level: SecurityLevel) -> List[Tuple[str, int]]:
        """Get candidates for digital signatures."""
        candidates = []
        
        if security_level == SecurityLevel.QUANTUM_RESISTANT:
            candidates.extend([
                ('Dilithium2', 2),
                ('Dilithium3', 3),
                ('Dilithium5', 5)
            ])
        else:
            candidates.extend([
                ('ECC', 256),
                ('RSA', 2048),
                ('RSA', 3072)
            ])
        
        return candidates
    
    def _generate_rationale(self, algorithm: str, purpose: CryptographicPurpose,
                          security_level: SecurityLevel, performance_priority: bool) -> str:
        """Generate rationale for algorithm selection."""
        rationale_parts = []
        
        # Algorithm-specific rationale
        if algorithm.startswith('Kyber'):
            rationale_parts.append("Post-quantum key encapsulation mechanism")
        elif algorithm.startswith('Dilithium'):
            rationale_parts.append("Post-quantum digital signature scheme")
        elif algorithm == 'AES-GCM':
            rationale_parts.append("Industry-standard authenticated encryption")
        elif algorithm == 'ChaCha20-Poly1305':
            rationale_parts.append("High-performance authenticated encryption")
        elif algorithm == 'ECC':
            rationale_parts.append("Efficient elliptic curve cryptography")
        elif algorithm == 'RSA':
            rationale_parts.append("Widely-supported public key algorithm")
        
        # Security level rationale
        if security_level == SecurityLevel.QUANTUM_RESISTANT:
            rationale_parts.append("provides quantum resistance")
        elif security_level == SecurityLevel.HIGH:
            rationale_parts.append("offers high security level")
        
        # Performance rationale
        if performance_priority:
            rationale_parts.append("optimized for performance")
        
        return "; ".join(rationale_parts)
    
    def create_hybrid_encryption_scheme(self, security_level: SecurityLevel) -> Dict[str, Any]:
        """Create a hybrid encryption scheme combining multiple algorithms."""
        scheme = {
            'timestamp': time.time(),
            'security_level': security_level.value,
            'components': {}
        }
        
        if security_level == SecurityLevel.QUANTUM_RESISTANT:
            # PQC hybrid scheme
            kem_alg, sig_alg = select_pqc_algorithm("high")
            scheme['components'] = {
                'key_encapsulation': kem_alg,
                'digital_signature': sig_alg,
                'symmetric_encryption': 'AES-GCM',
                'key_derivation': 'HKDF-SHA256'
            }
        else:
            # Traditional hybrid scheme
            scheme['components'] = {
                'key_exchange': 'ECC-P256',
                'digital_signature': 'ECC-P256',
                'symmetric_encryption': 'AES-GCM',
                'key_derivation': 'HKDF-SHA256'
            }
        
        return scheme
    
    def encrypt_with_recommended_algorithm(self, data: bytes, 
                                         security_level: SecurityLevel,
                                         recipient_identity: Optional[str] = None) -> Dict[str, Any]:
        """Encrypt data using recommended algorithms."""
        if recipient_identity and self.ibe_manager:
            # Use IBE if identity is provided
            return {
                'method': 'IBE',
                'data': self.ibe_manager.encrypt_to_identity(recipient_identity, data)
            }
        
        # Get recommendation
        recommendation = self.recommend_algorithm(
            CryptographicPurpose.DATA_ENCRYPTION, 
            security_level,
            len(data)
        )
        
        if recommendation.algorithm.startswith('Kyber'):
            # Use PQC hybrid encryption
            # For demonstration, we'll need a public key - in practice this would be provided
            pqc_kem = PQCKeyEncapsulation(recommendation.algorithm)
            pub_key, priv_key = pqc_kem.generate_keypair()
            
            ciphertext, encrypted_data = self.pqc_hybrid.encrypt_hybrid(pub_key, data)
            
            return {
                'method': 'PQC_Hybrid',
                'algorithm': recommendation.algorithm,
                'encapsulated_key': ciphertext.hex(),
                'encrypted_data': encrypted_data.hex(),
                'public_key': pub_key.hex(),  # Normally this would be known
                'rationale': recommendation.rationale
            }
        else:
            # Use traditional symmetric encryption
            key = os.urandom(32)  # In practice, derive from key exchange
            
            if recommendation.algorithm == 'AES-GCM':
                iv, ciphertext, tag = self.symmetric.encrypt_aes_gcm(key, data)
                return {
                    'method': 'Symmetric',
                    'algorithm': recommendation.algorithm,
                    'iv': iv.hex(),
                    'ciphertext': ciphertext.hex(),
                    'tag': tag.hex(),
                    'rationale': recommendation.rationale
                }
            elif recommendation.algorithm == 'ChaCha20-Poly1305':
                nonce, ciphertext = self.symmetric.encrypt_chacha20_poly1305(key, data)
                return {
                    'method': 'Symmetric',
                    'algorithm': recommendation.algorithm,
                    'nonce': nonce.hex(),
                    'ciphertext': ciphertext.hex(),
                    'rationale': recommendation.rationale
                }
    
    def get_algorithm_comparison(self, purpose: CryptographicPurpose) -> List[AlgorithmRecommendation]:
        """Get comparison of all suitable algorithms for a purpose."""
        recommendations = []
        
        for security_level in SecurityLevel:
            try:
                rec = self.recommend_algorithm(purpose, security_level)
                recommendations.append(rec)
            except Exception as e:
                self.logger.warning(f"Could not get recommendation for {security_level}: {e}")
        
        return sorted(recommendations, key=lambda x: x.overall_score, reverse=True)
    
    def validate_algorithm_compatibility(self, algorithms: List[str]) -> Dict[str, bool]:
        """Validate compatibility between different algorithms."""
        compatibility = {}
        
        for algorithm in algorithms:
            compatibility[algorithm] = {
                'quantum_resistant': self.algorithm_performance.get(algorithm, {}).get('quantum_resistant', False),
                'supported': algorithm in self.algorithm_performance,
                'recommended_key_sizes': self._get_recommended_key_sizes(algorithm)
            }
        
        return compatibility
    
    def _get_recommended_key_sizes(self, algorithm: str) -> List[int]:
        """Get recommended key sizes for an algorithm."""
        key_size_map = {
            'AES-GCM': [128, 192, 256],
            'ChaCha20-Poly1305': [256],
            'RSA': [2048, 3072, 4096],
            'ECC': [256, 384, 521],
            'Kyber512': [512],
            'Kyber768': [768],
            'Kyber1024': [1024],
            'Dilithium2': [2],
            'Dilithium3': [3],
            'Dilithium5': [5]
        }
        
        return key_size_map.get(algorithm, [])


# os imported at the top

