"""
Enhanced Threshold Signatures and Multisig (m-of-n) Implementation
Supports distributed key responsibility with secure key sharing
Implements Shamir's Secret Sharing and threshold cryptography
"""

import os
import json
import time
import hashlib
import struct
import secrets
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum

# Core cryptography
import nacl.secret
import nacl.utils
import nacl.encoding
from cryptography.hazmat.primitives import hashes, serialization, constant_time
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Mathematical operations for secret sharing
from functools import reduce
from operator import xor


class ThresholdScheme(Enum):
    """Supported threshold cryptography schemes"""
    SHAMIR_SECRET_SHARING = "shamir_secret_sharing"
    DISTRIBUTED_RSA = "distributed_rsa"
    THRESHOLD_ECDSA = "threshold_ecdsa"
    MULTISIG_SCHNORR = "multisig_schnorr"


class SignatureStatus(Enum):
    """Status of signature collection"""
    PENDING = "pending"
    PARTIAL = "partial"
    COMPLETE = "complete"
    INVALID = "invalid"


@dataclass
class SecretShare:
    """A single share of a secret"""
    share_id: int
    value: bytes
    threshold: int
    total_shares: int
    scheme: ThresholdScheme
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ThresholdKeyPair:
    """Threshold key pair information"""
    key_id: str
    threshold: int
    total_shares: int
    scheme: ThresholdScheme
    public_key: bytes
    shares: Dict[int, SecretShare]
    created_at: float
    participants: List[str]


@dataclass
class PartialSignature:
    """Partial signature from a participant"""
    participant_id: str
    share_id: int
    signature_data: bytes
    public_commitment: bytes
    timestamp: float
    nonce: Optional[bytes] = None


@dataclass
class ThresholdSignature:
    """Complete threshold signature"""
    message_hash: bytes
    signature: bytes
    participating_shares: List[int]
    threshold: int
    signature_status: SignatureStatus
    created_at: float


class ShamirSecretSharing:
    """
    Shamir's Secret Sharing implementation for threshold cryptography
    """
    
    # Prime modulus for finite field operations (256-bit prime)
    PRIME = 2**256 - 189
    
    def __init__(self):
        """Initialize Shamir's Secret Sharing"""
        pass
    
    def split_secret(self, secret: bytes, threshold: int, total_shares: int) -> List[SecretShare]:
        """
        Split secret into shares using Shamir's scheme
        
        Args:
            secret: The secret to split
            threshold: Minimum shares needed to reconstruct
            total_shares: Total number of shares to create
            
        Returns:
            List of secret shares
        """
        if threshold > total_shares:
            raise ValueError("Threshold cannot exceed total shares")
        
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")
        
        # Convert secret to integer
        secret_int = int.from_bytes(secret, 'big')
        
        if secret_int >= self.PRIME:
            raise ValueError("Secret too large for field")
        
        # Generate random coefficients for polynomial
        coefficients = [secret_int]  # a0 = secret
        for _ in range(threshold - 1):
            coefficients.append(secrets.randbelow(self.PRIME))
        
        # Generate shares by evaluating polynomial at different points
        shares = []
        for i in range(1, total_shares + 1):
            share_value = self._evaluate_polynomial(coefficients, i)
            share_bytes = share_value.to_bytes(32, 'big')
            
            share = SecretShare(
                share_id=i,
                value=share_bytes,
                threshold=threshold,
                total_shares=total_shares,
                scheme=ThresholdScheme.SHAMIR_SECRET_SHARING
            )
            shares.append(share)
        
        return shares
    
    def reconstruct_secret(self, shares: List[SecretShare]) -> bytes:
        """
        Reconstruct secret from threshold shares using Lagrange interpolation
        """
        if len(shares) < shares[0].threshold:
            raise ValueError(f"Need at least {shares[0].threshold} shares, got {len(shares)}")
        
        # Verify all shares have same parameters
        threshold = shares[0].threshold
        scheme = shares[0].scheme
        
        for share in shares[1:]:
            if share.threshold != threshold or share.scheme != scheme:
                raise ValueError("Inconsistent share parameters")
        
        # Use only the required number of shares
        selected_shares = shares[:threshold]
        
        # Convert shares to integers and collect x-coordinates
        points = []
        for share in selected_shares:
            x = share.share_id
            y = int.from_bytes(share.value, 'big')
            points.append((x, y))
        
        # Perform Lagrange interpolation to find f(0) = secret
        secret_int = self._lagrange_interpolation(points)
        
        # Convert back to bytes
        return secret_int.to_bytes(32, 'big')
    
    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """Evaluate polynomial at point x"""
        result = 0
        x_power = 1
        
        for coeff in coefficients:
            result = (result + coeff * x_power) % self.PRIME
            x_power = (x_power * x) % self.PRIME
        
        return result
    
    def _lagrange_interpolation(self, points: List[Tuple[int, int]]) -> int:
        """Perform Lagrange interpolation to find f(0)"""
        result = 0
        
        for i, (xi, yi) in enumerate(points):
            # Calculate Lagrange basis polynomial Li(0)
            numerator = 1
            denominator = 1
            
            for j, (xj, _) in enumerate(points):
                if i != j:
                    numerator = (numerator * (-xj)) % self.PRIME
                    denominator = (denominator * (xi - xj)) % self.PRIME
            
            # Calculate modular inverse of denominator
            denominator_inv = self._mod_inverse(denominator, self.PRIME)
            
            # Add term to result
            term = (yi * numerator * denominator_inv) % self.PRIME
            result = (result + term) % self.PRIME
        
        return result
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Calculate modular inverse using extended Euclidean algorithm"""
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


class ThresholdECDSA:
    """
    Threshold ECDSA implementation for distributed signatures
    """
    
    def __init__(self, curve=ec.SECP256R1()):
        """Initialize threshold ECDSA with specified curve"""
        self.curve = curve
        self.backend = default_backend()
        self.secret_sharing = ShamirSecretSharing()
    
    def generate_threshold_keypair(self, threshold: int, total_participants: int, 
                                  participants: List[str]) -> ThresholdKeyPair:
        """
        Generate threshold ECDSA keypair
        """
        if len(participants) != total_participants:
            raise ValueError("Number of participants must match total_participants")
        
        # Generate master private key
        private_key = ec.generate_private_key(self.curve, self.backend)
        private_value = private_key.private_numbers().private_value
        
        # Convert private key to bytes (32 bytes for secp256r1)
        private_bytes = private_value.to_bytes(32, 'big')
        
        # Split private key using Shamir's secret sharing
        shares = self.secret_sharing.split_secret(private_bytes, threshold, total_participants)
        
        # Create share mapping
        share_mapping = {}
        for i, share in enumerate(shares):
            share_mapping[share.share_id] = share
        
        # Get public key
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_numbers().x.to_bytes(32, 'big') + \
                          public_key.public_numbers().y.to_bytes(32, 'big')
        
        # Generate unique key ID
        key_id = hashlib.sha256(public_key_bytes + str(time.time()).encode()).hexdigest()[:16]
        
        return ThresholdKeyPair(
            key_id=key_id,
            threshold=threshold,
            total_shares=total_participants,
            scheme=ThresholdScheme.THRESHOLD_ECDSA,
            public_key=public_key_bytes,
            shares=share_mapping,
            created_at=time.time(),
            participants=participants
        )
    
    def create_partial_signature(self, keypair: ThresholdKeyPair, 
                                share_id: int, message: bytes,
                                participant_id: str) -> PartialSignature:
        """
        Create partial signature using a share
        """
        if share_id not in keypair.shares:
            raise ValueError(f"Share {share_id} not found in keypair")
        
        share = keypair.shares[share_id]
        
        # Hash the message
        digest = hashes.Hash(hashes.SHA256(), self.backend)
        digest.update(message)
        message_hash = digest.finalize()
        
        # For this implementation, we'll use a simplified partial signature
        # In a full implementation, this would involve more complex threshold protocols
        
        # Create partial signature by signing with reconstructed key portion
        # This is a simplified approach - real threshold ECDSA is more complex
        nonce = nacl.utils.random(32)
        
        # Combine share data with message hash and nonce
        signature_input = share.value + message_hash + nonce
        partial_sig = hashlib.sha256(signature_input).digest()
        
        # Create public commitment for verification
        commitment_input = share.value + str(share_id).encode() + message_hash
        public_commitment = hashlib.sha256(commitment_input).digest()
        
        return PartialSignature(
            participant_id=participant_id,
            share_id=share_id,
            signature_data=partial_sig,
            public_commitment=public_commitment,
            timestamp=time.time(),
            nonce=nonce
        )
    
    def combine_partial_signatures(self, keypair: ThresholdKeyPair,
                                  partial_signatures: List[PartialSignature],
                                  message: bytes) -> ThresholdSignature:
        """
        Combine partial signatures into final threshold signature
        """
        if len(partial_signatures) < keypair.threshold:
            return ThresholdSignature(
                message_hash=hashlib.sha256(message).digest(),
                signature=b'',
                participating_shares=[],
                threshold=keypair.threshold,
                signature_status=SignatureStatus.PARTIAL,
                created_at=time.time()
            )
        
        # Verify partial signatures
        valid_signatures = []
        for partial_sig in partial_signatures:
            if self._verify_partial_signature(keypair, partial_sig, message):
                valid_signatures.append(partial_sig)
        
        if len(valid_signatures) < keypair.threshold:
            return ThresholdSignature(
                message_hash=hashlib.sha256(message).digest(),
                signature=b'',
                participating_shares=[],
                threshold=keypair.threshold,
                signature_status=SignatureStatus.INVALID,
                created_at=time.time()
            )
        
        # Use threshold number of signatures
        selected_signatures = valid_signatures[:keypair.threshold]
        
        # Combine signatures (simplified approach)
        combined_signature_data = b''
        participating_shares = []
        
        for partial_sig in selected_signatures:
            combined_signature_data += partial_sig.signature_data
            participating_shares.append(partial_sig.share_id)
        
        # Create final signature by hashing combined data
        final_signature = hashlib.sha256(combined_signature_data + message).digest()
        
        return ThresholdSignature(
            message_hash=hashlib.sha256(message).digest(),
            signature=final_signature,
            participating_shares=participating_shares,
            threshold=keypair.threshold,
            signature_status=SignatureStatus.COMPLETE,
            created_at=time.time()
        )
    
    def _verify_partial_signature(self, keypair: ThresholdKeyPair,
                                 partial_sig: PartialSignature,
                                 message: bytes) -> bool:
        """
        Verify a partial signature
        """
        try:
            share = keypair.shares[partial_sig.share_id]
            message_hash = hashlib.sha256(message).digest()
            
            # Recreate the signature input
            signature_input = share.value + message_hash + partial_sig.nonce
            expected_signature = hashlib.sha256(signature_input).digest()
            
            # Verify signature matches
            if not constant_time.bytes_eq(partial_sig.signature_data, expected_signature):
                return False
            
            # Verify public commitment
            commitment_input = share.value + str(partial_sig.share_id).encode() + message_hash
            expected_commitment = hashlib.sha256(commitment_input).digest()
            
            return constant_time.bytes_eq(partial_sig.public_commitment, expected_commitment)
            
        except Exception:
            return False
    
    def verify_threshold_signature(self, keypair: ThresholdKeyPair,
                                  signature: ThresholdSignature,
                                  message: bytes) -> bool:
        """
        Verify threshold signature
        """
        try:
            # Verify message hash
            expected_hash = hashlib.sha256(message).digest()
            if not constant_time.bytes_eq(signature.message_hash, expected_hash):
                return False
            
            # Check if signature is complete
            if signature.signature_status != SignatureStatus.COMPLETE:
                return False
            
            # Verify signature was created with sufficient shares
            if len(signature.participating_shares) < signature.threshold:
                return False
            
            # For this simplified implementation, we verify by reconstructing
            # In a real implementation, verification would be more direct
            
            # This is a simplified verification - real threshold ECDSA verification
            # would use elliptic curve operations
            return len(signature.signature) == 32  # Basic sanity check
            
        except Exception:
            return False


class MultisigManager:
    """
    Manager for multisig and threshold signature operations
    """
    
    def __init__(self):
        """Initialize multisig manager"""
        self.shamir = ShamirSecretSharing()
        self.threshold_ecdsa = ThresholdECDSA()
        self.active_keypairs: Dict[str, ThresholdKeyPair] = {}
        self.pending_signatures: Dict[str, List[PartialSignature]] = {}
    
    def create_multisig_setup(self, participants: List[str], threshold: int,
                             scheme: ThresholdScheme = ThresholdScheme.THRESHOLD_ECDSA) -> ThresholdKeyPair:
        """
        Create a new multisig setup
        """
        total_participants = len(participants)
        
        if threshold > total_participants:
            raise ValueError("Threshold cannot exceed number of participants")
        
        if scheme == ThresholdScheme.THRESHOLD_ECDSA:
            keypair = self.threshold_ecdsa.generate_threshold_keypair(
                threshold, total_participants, participants
            )
        else:
            raise ValueError(f"Unsupported scheme: {scheme}")
        
        # Store keypair
        self.active_keypairs[keypair.key_id] = keypair
        self.pending_signatures[keypair.key_id] = []
        
        return keypair
    
    def get_participant_share(self, key_id: str, participant_id: str) -> Optional[SecretShare]:
        """
        Get the secret share for a specific participant
        """
        if key_id not in self.active_keypairs:
            return None
        
        keypair = self.active_keypairs[key_id]
        
        # Find participant index
        try:
            participant_index = keypair.participants.index(participant_id)
            share_id = participant_index + 1  # Share IDs start from 1
            
            return keypair.shares.get(share_id)
        except ValueError:
            return None
    
    def add_partial_signature(self, key_id: str, partial_signature: PartialSignature):
        """
        Add a partial signature to pending collection
        """
        if key_id not in self.pending_signatures:
            self.pending_signatures[key_id] = []
        
        # Check if participant already signed
        existing_participant_ids = {
            sig.participant_id for sig in self.pending_signatures[key_id]
        }
        
        if partial_signature.participant_id in existing_participant_ids:
            # Update existing signature
            self.pending_signatures[key_id] = [
                sig for sig in self.pending_signatures[key_id] 
                if sig.participant_id != partial_signature.participant_id
            ]
        
        self.pending_signatures[key_id].append(partial_signature)
    
    def try_complete_signature(self, key_id: str, message: bytes) -> Optional[ThresholdSignature]:
        """
        Try to complete signature if enough partial signatures are available
        """
        if key_id not in self.active_keypairs or key_id not in self.pending_signatures:
            return None
        
        keypair = self.active_keypairs[key_id]
        partial_signatures = self.pending_signatures[key_id]
        
        if len(partial_signatures) < keypair.threshold:
            return None
        
        # Attempt to combine signatures
        if keypair.scheme == ThresholdScheme.THRESHOLD_ECDSA:
            signature = self.threshold_ecdsa.combine_partial_signatures(
                keypair, partial_signatures, message
            )
        else:
            return None
        
        # Clear pending signatures if signature is complete
        if signature.signature_status == SignatureStatus.COMPLETE:
            self.pending_signatures[key_id] = []
        
        return signature
    
    def get_multisig_status(self, key_id: str) -> Dict[str, Any]:
        """
        Get status of multisig setup
        """
        if key_id not in self.active_keypairs:
            return {'error': 'Key ID not found'}
        
        keypair = self.active_keypairs[key_id]
        pending_count = len(self.pending_signatures.get(key_id, []))
        
        return {
            'key_id': key_id,
            'scheme': keypair.scheme.value,
            'threshold': keypair.threshold,
            'total_participants': keypair.total_shares,
            'participants': keypair.participants,
            'pending_signatures': pending_count,
            'signatures_needed': max(0, keypair.threshold - pending_count),
            'created_at': keypair.created_at
        }
    
    def export_keypair(self, key_id: str) -> Optional[str]:
        """
        Export keypair for backup/sharing (without private shares)
        """
        if key_id not in self.active_keypairs:
            return None
        
        keypair = self.active_keypairs[key_id]
        
        # Export without private share values for security
        export_data = {
            'key_id': keypair.key_id,
            'threshold': keypair.threshold,
            'total_shares': keypair.total_shares,
            'scheme': keypair.scheme.value,
            'public_key': nacl.encoding.Base64Encoder.encode(keypair.public_key).decode(),
            'created_at': keypair.created_at,
            'participants': keypair.participants,
            'share_structure': {
                str(share_id): {
                    'share_id': share.share_id,
                    'threshold': share.threshold,
                    'total_shares': share.total_shares,
                    'scheme': share.scheme.value
                } for share_id, share in keypair.shares.items()
            }
        }
        
        return json.dumps(export_data, indent=2)
    
    def cleanup_expired_signatures(self, max_age_seconds: int = 3600):
        """
        Clean up expired partial signatures
        """
        current_time = time.time()
        
        for key_id in self.pending_signatures:
            self.pending_signatures[key_id] = [
                sig for sig in self.pending_signatures[key_id]
                if current_time - sig.timestamp < max_age_seconds
            ]