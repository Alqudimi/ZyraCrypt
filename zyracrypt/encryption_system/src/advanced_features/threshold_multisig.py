"""
Threshold Signatures and Multisig (m-of-n) Implementation

This module provides threshold cryptography and multi-signature schemes for
distributed key responsibility and enhanced security through key sharing.
"""

import os
import json
import time
import secrets
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod

# Cryptographic imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.backends import default_backend

# Side-channel protection
from .side_channel_protection import SideChannelGuard, timing_safe


class SignatureScheme(Enum):
    """Supported signature schemes for multisig."""
    ED25519 = "ed25519"
    ECDSA_P256 = "ecdsa_p256" 
    ECDSA_P384 = "ecdsa_p384"
    RSA_PSS = "rsa_pss"


class ThresholdType(Enum):
    """Types of threshold schemes."""
    SIMPLE_MULTISIG = "simple_multisig"      # Basic m-of-n signatures
    SHAMIR_THRESHOLD = "shamir_threshold"    # Shamir's secret sharing
    FROST_ED25519 = "frost_ed25519"         # FROST for Ed25519
    FROST_ECDSA = "frost_ecdsa"             # FROST for ECDSA


@dataclass
class MultisigPolicy:
    """Policy definition for multi-signature schemes."""
    scheme_id: str
    signature_scheme: SignatureScheme
    threshold_type: ThresholdType
    threshold: int          # m in m-of-n
    total_signers: int      # n in m-of-n
    required_signers: Set[str] = None  # Optional: specific required signers
    timeout_seconds: Optional[int] = None
    description: Optional[str] = None
    created_at: float = 0
    
    def __post_init__(self):
        if self.created_at == 0:
            self.created_at = time.time()
        if self.required_signers is None:
            self.required_signers = set()
        if self.threshold > self.total_signers:
            raise ValueError("Threshold cannot exceed total signers")
        if len(self.required_signers) > self.threshold:
            raise ValueError("Required signers cannot exceed threshold")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['signature_scheme'] = self.signature_scheme.value
        result['threshold_type'] = self.threshold_type.value
        result['required_signers'] = list(self.required_signers)
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MultisigPolicy':
        """Create from dictionary."""
        data['signature_scheme'] = SignatureScheme(data['signature_scheme'])
        data['threshold_type'] = ThresholdType(data['threshold_type'])
        data['required_signers'] = set(data.get('required_signers', []))
        return cls(**data)


@dataclass
class SignerInfo:
    """Information about a multisig participant."""
    signer_id: str
    public_key: bytes
    weight: int = 1  # For weighted voting schemes
    active: bool = True
    last_signed: Optional[float] = None
    signature_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['public_key'] = result['public_key'].hex()
        return result
    
    @classmethod  
    def from_dict(cls, data: Dict[str, Any]) -> 'SignerInfo':
        """Create from dictionary."""
        data['public_key'] = bytes.fromhex(data['public_key'])
        return cls(**data)


@dataclass
class PartialSignature:
    """A partial signature from one signer."""
    signer_id: str
    signature: bytes
    public_key: bytes
    timestamp: float
    signature_scheme: SignatureScheme
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'signer_id': self.signer_id,
            'signature': self.signature.hex(),
            'public_key': self.public_key.hex(),
            'timestamp': self.timestamp,
            'signature_scheme': self.signature_scheme.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PartialSignature':
        """Create from dictionary."""
        return cls(
            signer_id=data['signer_id'],
            signature=bytes.fromhex(data['signature']),
            public_key=bytes.fromhex(data['public_key']),
            timestamp=data['timestamp'],
            signature_scheme=SignatureScheme(data['signature_scheme'])
        )


class ThresholdSigner(ABC):
    """Abstract base class for threshold signing implementations."""
    
    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a keypair for this signature scheme."""
        pass
    
    @abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Create a signature with the private key."""
        pass
    
    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature."""
        pass
    
    @abstractmethod
    def aggregate_signatures(self, signatures: List[PartialSignature], 
                           message: bytes) -> Optional[bytes]:
        """Aggregate multiple partial signatures into a final signature."""
        pass


class Ed25519ThresholdSigner(ThresholdSigner):
    """Ed25519-based threshold signer."""
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return private_bytes, public_bytes
    
    @timing_safe
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign message with Ed25519."""
        ed25519_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        return ed25519_key.sign(message)
    
    @timing_safe
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify Ed25519 signature."""
        try:
            ed25519_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            ed25519_key.verify(signature, message)
            return True
        except Exception:
            return False
    
    def aggregate_signatures(self, signatures: List[PartialSignature], 
                           message: bytes) -> Optional[bytes]:
        """
        For simple Ed25519 multisig, we concatenate signatures.
        Note: This is not a true threshold signature scheme like FROST.
        """
        if not signatures:
            return None
        
        # Verify all signatures first
        for sig in signatures:
            if not self.verify(sig.public_key, message, sig.signature):
                return None
        
        # Simple concatenation for multisig (not cryptographically aggregated)
        aggregated = b''
        for sig in signatures:
            aggregated += sig.signature
        
        return aggregated


class ECDSAThresholdSigner(ThresholdSigner):
    """ECDSA-based threshold signer."""
    
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ECDSA keypair."""
        private_key = ec.generate_private_key(self.curve, default_backend())
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_bytes, public_bytes
    
    @timing_safe
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign message with ECDSA."""
        ecdsa_key = serialization.load_der_private_key(
            private_key, password=None, backend=default_backend()
        )
        signature = ecdsa_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature
    
    @timing_safe
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify ECDSA signature."""
        try:
            ecdsa_key = serialization.load_der_public_key(
                public_key, backend=default_backend()
            )
            ecdsa_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
    
    def aggregate_signatures(self, signatures: List[PartialSignature], 
                           message: bytes) -> Optional[bytes]:
        """Aggregate ECDSA signatures (simple concatenation)."""
        if not signatures:
            return None
        
        # Verify all signatures first
        for sig in signatures:
            if not self.verify(sig.public_key, message, sig.signature):
                return None
        
        # Simple concatenation for multisig
        aggregated = b''
        for sig in signatures:
            aggregated += sig.signature
        
        return aggregated


class ShamirSecretSharing:
    """Shamir's Secret Sharing implementation for threshold schemes."""
    
    def __init__(self, prime: int = None):
        # Use a large prime for the finite field
        self.prime = prime or (2**521 - 1)  # Mersenne prime
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Compute modular inverse using extended Euclidean algorithm."""
        if a < 0:
            a = (a % m + m) % m
        
        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        
        return (x % m + m) % m
    
    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """Evaluate polynomial at point x."""
        result = 0
        for i, coeff in enumerate(coefficients):
            result = (result + coeff * pow(x, i, self.prime)) % self.prime
        return result
    
    def split_secret(self, secret: int, threshold: int, 
                    total_shares: int) -> List[Tuple[int, int]]:
        """
        Split a secret into shares using Shamir's scheme.
        
        Args:
            secret: The secret to split
            threshold: Minimum shares needed to reconstruct
            total_shares: Total number of shares to create
            
        Returns:
            List of (x, y) coordinate pairs representing shares
        """
        if threshold > total_shares:
            raise ValueError("Threshold cannot exceed total shares")
        
        # Generate random coefficients for polynomial
        coefficients = [secret]  # a0 = secret
        for _ in range(threshold - 1):
            coefficients.append(secrets.randbelow(self.prime))
        
        # Generate shares by evaluating polynomial at different points
        shares = []
        for i in range(1, total_shares + 1):
            x = i
            y = self._evaluate_polynomial(coefficients, x)
            shares.append((x, y))
        
        return shares
    
    def reconstruct_secret(self, shares: List[Tuple[int, int]]) -> int:
        """
        Reconstruct secret from shares using Lagrange interpolation.
        
        Args:
            shares: List of (x, y) coordinate pairs
            
        Returns:
            Reconstructed secret
        """
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares to reconstruct")
        
        # Lagrange interpolation
        secret = 0
        for i, (xi, yi) in enumerate(shares):
            # Calculate Lagrange basis polynomial
            li = 1
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    # li *= (0 - xj) / (xi - xj)
                    numerator = (-xj) % self.prime
                    denominator = (xi - xj) % self.prime
                    li = (li * numerator * self._mod_inverse(denominator, self.prime)) % self.prime
            
            secret = (secret + yi * li) % self.prime
        
        return secret


class MultisigManager:
    """Manager for multi-signature operations and threshold schemes."""
    
    def __init__(self, storage_path: str = "./multisig_data.json"):
        self.storage_path = storage_path
        self.policies: Dict[str, MultisigPolicy] = {}
        self.signers: Dict[str, Dict[str, SignerInfo]] = {}  # scheme_id -> signer_id -> info
        self.pending_signatures: Dict[str, List[PartialSignature]] = {}
        
        # Signature scheme implementations
        self.signers_map = {
            SignatureScheme.ED25519: Ed25519ThresholdSigner(),
            SignatureScheme.ECDSA_P256: ECDSAThresholdSigner(ec.SECP256R1()),
            SignatureScheme.ECDSA_P384: ECDSAThresholdSigner(ec.SECP384R1()),
        }
        
        # Shamir secret sharing
        self.shamir = ShamirSecretSharing()
        
        # Load existing data
        self._load_data()
    
    def _load_data(self):
        """Load multisig data from storage."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                
                # Load policies
                for scheme_id, policy_data in data.get('policies', {}).items():
                    self.policies[scheme_id] = MultisigPolicy.from_dict(policy_data)
                
                # Load signers
                for scheme_id, scheme_signers in data.get('signers', {}).items():
                    self.signers[scheme_id] = {}
                    for signer_id, signer_data in scheme_signers.items():
                        self.signers[scheme_id][signer_id] = SignerInfo.from_dict(signer_data)
                
                # Load pending signatures
                for msg_id, sigs_data in data.get('pending_signatures', {}).items():
                    self.pending_signatures[msg_id] = []
                    for sig_data in sigs_data:
                        self.pending_signatures[msg_id].append(
                            PartialSignature.from_dict(sig_data)
                        )
                        
            except Exception as e:
                print(f"Error loading multisig data: {e}")
    
    def _save_data(self):
        """Save multisig data to storage."""
        data = {
            'policies': {k: v.to_dict() for k, v in self.policies.items()},
            'signers': {
                scheme_id: {signer_id: signer.to_dict() 
                           for signer_id, signer in scheme_signers.items()}
                for scheme_id, scheme_signers in self.signers.items()
            },
            'pending_signatures': {
                msg_id: [sig.to_dict() for sig in sigs]
                for msg_id, sigs in self.pending_signatures.items()
            }
        }
        
        os.makedirs(os.path.dirname(self.storage_path) if os.path.dirname(self.storage_path) else '.', exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def create_multisig_scheme(self, policy: MultisigPolicy, 
                             signer_public_keys: Dict[str, bytes]) -> str:
        """
        Create a new multisig scheme.
        
        Args:
            policy: Multisig policy configuration
            signer_public_keys: Dictionary of signer_id -> public_key
            
        Returns:
            Scheme ID
        """
        if len(signer_public_keys) != policy.total_signers:
            raise ValueError("Number of signers doesn't match policy")
        
        # Validate signature scheme is supported
        if policy.signature_scheme not in self.signers_map:
            raise ValueError(f"Unsupported signature scheme: {policy.signature_scheme}")
        
        # Store policy
        self.policies[policy.scheme_id] = policy
        
        # Store signers
        self.signers[policy.scheme_id] = {}
        for signer_id, public_key in signer_public_keys.items():
            self.signers[policy.scheme_id][signer_id] = SignerInfo(
                signer_id=signer_id,
                public_key=public_key
            )
        
        self._save_data()
        return policy.scheme_id
    
    def add_partial_signature(self, scheme_id: str, message: bytes, 
                            signer_id: str, signature: bytes) -> bool:
        """
        Add a partial signature to a multisig operation.
        
        Args:
            scheme_id: Multisig scheme identifier
            message: Message being signed
            signer_id: ID of the signer
            signature: Partial signature
            
        Returns:
            True if signature was added successfully
        """
        if scheme_id not in self.policies:
            raise ValueError(f"Unknown scheme: {scheme_id}")
        
        policy = self.policies[scheme_id]
        
        if signer_id not in self.signers[scheme_id]:
            raise ValueError(f"Unknown signer: {signer_id}")
        
        signer_info = self.signers[scheme_id][signer_id]
        
        if not signer_info.active:
            raise ValueError(f"Signer is not active: {signer_id}")
        
        # Verify signature
        signer_impl = self.signers_map[policy.signature_scheme]
        if not signer_impl.verify(signer_info.public_key, message, signature):
            return False
        
        # Create message ID for tracking
        message_id = hashlib.sha256(message + scheme_id.encode()).hexdigest()
        
        # Initialize pending signatures for this message if needed
        if message_id not in self.pending_signatures:
            self.pending_signatures[message_id] = []
        
        # Check if this signer has already signed
        for existing_sig in self.pending_signatures[message_id]:
            if existing_sig.signer_id == signer_id:
                return False  # Already signed
        
        # Add partial signature
        partial_sig = PartialSignature(
            signer_id=signer_id,
            signature=signature,
            public_key=signer_info.public_key,
            timestamp=time.time(),
            signature_scheme=policy.signature_scheme
        )
        
        self.pending_signatures[message_id].append(partial_sig)
        
        # Update signer statistics
        signer_info.last_signed = time.time()
        signer_info.signature_count += 1
        
        self._save_data()
        return True
    
    def try_aggregate_signature(self, scheme_id: str, message: bytes) -> Optional[bytes]:
        """
        Try to aggregate signatures if threshold is met.
        
        Args:
            scheme_id: Multisig scheme identifier
            message: Message being signed
            
        Returns:
            Aggregated signature if threshold met, None otherwise
        """
        if scheme_id not in self.policies:
            raise ValueError(f"Unknown scheme: {scheme_id}")
        
        policy = self.policies[scheme_id]
        message_id = hashlib.sha256(message + scheme_id.encode()).hexdigest()
        
        if message_id not in self.pending_signatures:
            return None
        
        signatures = self.pending_signatures[message_id]
        
        # Check if threshold is met
        if len(signatures) < policy.threshold:
            return None
        
        # Check required signers if specified
        if policy.required_signers:
            signed_by_required = {sig.signer_id for sig in signatures if sig.signer_id in policy.required_signers}
            if len(signed_by_required) < len(policy.required_signers):
                return None
        
        # Check timeout if specified
        if policy.timeout_seconds:
            current_time = time.time()
            oldest_sig_time = min(sig.timestamp for sig in signatures)
            if current_time - oldest_sig_time > policy.timeout_seconds:
                # Timeout exceeded, remove expired signatures
                del self.pending_signatures[message_id]
                self._save_data()
                return None
        
        # Aggregate signatures
        signer_impl = self.signers_map[policy.signature_scheme]
        
        # Use first threshold signatures
        selected_signatures = signatures[:policy.threshold]
        aggregated_signature = signer_impl.aggregate_signatures(selected_signatures, message)
        
        if aggregated_signature:
            # Clean up pending signatures
            del self.pending_signatures[message_id]
            self._save_data()
        
        return aggregated_signature
    
    def verify_multisig(self, scheme_id: str, message: bytes, 
                       aggregated_signature: bytes) -> bool:
        """
        Verify an aggregated multisig signature.
        
        Args:
            scheme_id: Multisig scheme identifier
            message: Original message
            aggregated_signature: Aggregated signature to verify
            
        Returns:
            True if signature is valid
        """
        if scheme_id not in self.policies:
            return False
        
        policy = self.policies[scheme_id]
        signer_impl = self.signers_map[policy.signature_scheme]
        
        # For simple concatenated signatures, we need to split and verify each
        # This is a simplified implementation - real threshold schemes like FROST
        # would have different verification logic
        
        if policy.signature_scheme == SignatureScheme.ED25519:
            # Ed25519 signatures are 64 bytes each
            sig_length = 64
            if len(aggregated_signature) % sig_length != 0:
                return False
            
            num_sigs = len(aggregated_signature) // sig_length
            if num_sigs < policy.threshold:
                return False
            
            # Extract individual signatures (this is simplified)
            # In practice, we'd need metadata about which signers contributed
            signers_list = list(self.signers[scheme_id].values())[:num_sigs]
            
            for i in range(num_sigs):
                start_idx = i * sig_length
                end_idx = start_idx + sig_length
                individual_sig = aggregated_signature[start_idx:end_idx]
                
                if not signer_impl.verify(signers_list[i].public_key, message, individual_sig):
                    return False
            
            return True
        
        # Similar logic for other signature schemes...
        return False
    
    def get_scheme_info(self, scheme_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a multisig scheme."""
        if scheme_id not in self.policies:
            return None
        
        policy = self.policies[scheme_id]
        signers = self.signers.get(scheme_id, {})
        
        return {
            'policy': policy.to_dict(),
            'signers': {k: v.to_dict() for k, v in signers.items()},
            'active_signers': sum(1 for s in signers.values() if s.active),
            'total_signatures': sum(s.signature_count for s in signers.values())
        }
    
    def list_schemes(self) -> List[str]:
        """List all multisig scheme IDs."""
        return list(self.policies.keys())
    
    def revoke_signer(self, scheme_id: str, signer_id: str) -> bool:
        """Revoke a signer from a multisig scheme."""
        if (scheme_id not in self.signers or 
            signer_id not in self.signers[scheme_id]):
            return False
        
        self.signers[scheme_id][signer_id].active = False
        self._save_data()
        return True
    
    def get_pending_signatures_count(self, scheme_id: str, message: bytes) -> int:
        """Get count of pending signatures for a message."""
        message_id = hashlib.sha256(message + scheme_id.encode()).hexdigest()
        return len(self.pending_signatures.get(message_id, []))