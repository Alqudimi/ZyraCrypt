"""
Secure Multi-Party Computation (MPC) Implementation

This module implements practical MPC protocols for privacy-preserving computations:
- Private sum computation (additive secret sharing)
- Private set intersection (PSI)
- Private comparison protocols
- Secure aggregation

Enables multiple parties to jointly compute functions while keeping inputs private.
"""

import os
import hashlib
import secrets
import json
from typing import List, Set, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hmac


class MPCProtocolType(Enum):
    """Types of MPC protocols."""
    ADDITIVE_SECRET_SHARING = "additive_secret_sharing"
    PRIVATE_SET_INTERSECTION = "private_set_intersection"
    SECURE_COMPARISON = "secure_comparison"
    SECURE_AGGREGATION = "secure_aggregation"


@dataclass
class MPCShare:
    """A share in multi-party computation."""
    party_id: str
    share_value: int
    protocol: MPCProtocolType
    computation_id: str


@dataclass
class MPCResult:
    """Result of MPC computation."""
    computation_id: str
    result: Any
    protocol: MPCProtocolType
    participants: List[str]
    verified: bool = False


class AdditiveSecretSharing:
    """
    Additive Secret Sharing for secure sum computation.
    
    Allows multiple parties to compute sum of their private inputs
    without revealing individual values.
    """
    
    def __init__(self, modulus: int = 2**64):
        """Initialize with a modulus for finite field operations."""
        self.modulus = modulus
    
    def share_secret(self, secret: int, num_parties: int) -> List[int]:
        """
        Split a secret into additive shares.
        
        Args:
            secret: The secret integer to share
            num_parties: Number of parties to split among
            
        Returns:
            List of shares (one per party)
        """
        if num_parties < 2:
            raise ValueError("Need at least 2 parties for MPC")
        
        # Generate random shares for n-1 parties
        shares = [secrets.randbelow(self.modulus) for _ in range(num_parties - 1)]
        
        # Last share is computed to maintain sum property
        last_share = (secret - sum(shares)) % self.modulus
        shares.append(last_share)
        
        return shares
    
    def reconstruct_secret(self, shares: List[int]) -> int:
        """
        Reconstruct secret from additive shares.
        
        Args:
            shares: List of additive shares
            
        Returns:
            Reconstructed secret
        """
        return sum(shares) % self.modulus
    
    def add_shares(self, share1: int, share2: int) -> int:
        """
        Add two shares locally (used for secure aggregation).
        
        Args:
            share1: First share
            share2: Second share
            
        Returns:
            Sum of shares
        """
        return (share1 + share2) % self.modulus
    
    def multiply_share_by_constant(self, share: int, constant: int) -> int:
        """
        Multiply a share by a public constant.
        
        Args:
            share: The share
            constant: Public constant
            
        Returns:
            Scaled share
        """
        return (share * constant) % self.modulus


class PrivateSetIntersection:
    """
    Private Set Intersection (PSI) using cryptographic hashing.
    
    Allows two parties to find common elements in their sets
    without revealing non-intersecting elements.
    """
    
    def __init__(self):
        """Initialize PSI protocol."""
        self.hash_key = None
    
    def setup_protocol(self) -> bytes:
        """
        Setup PSI protocol with a random key.
        
        Returns:
            The hash key (to be shared with other party)
        """
        self.hash_key = os.urandom(32)
        return self.hash_key
    
    def hash_set(self, input_set: Set[Any], hash_key: bytes) -> Set[bytes]:
        """
        Hash elements of a set using keyed hash.
        
        Args:
            input_set: Input set of elements
            hash_key: Shared hash key
            
        Returns:
            Set of hashed elements
        """
        hashed_set = set()
        for element in input_set:
            # Convert element to bytes if needed
            if isinstance(element, str):
                element_bytes = element.encode('utf-8')
            elif isinstance(element, int):
                element_bytes = str(element).encode('utf-8')
            elif isinstance(element, bytes):
                element_bytes = element
            else:
                element_bytes = str(element).encode('utf-8')
            
            # Use HMAC for keyed hashing
            hashed = hmac.new(hash_key, element_bytes, hashlib.sha256).digest()
            hashed_set.add(hashed)
        
        return hashed_set
    
    def compute_intersection(self, hashed_set1: Set[bytes], 
                           hashed_set2: Set[bytes]) -> Set[bytes]:
        """
        Compute intersection of two hashed sets.
        
        Args:
            hashed_set1: First hashed set
            hashed_set2: Second hashed set
            
        Returns:
            Intersection of hashed sets
        """
        return hashed_set1 & hashed_set2
    
    def psi_protocol(self, my_set: Set[Any], other_hashed_set: Set[bytes], 
                     hash_key: bytes) -> Set[bytes]:
        """
        Complete PSI protocol from one party's perspective.
        
        Args:
            my_set: This party's input set
            other_hashed_set: Other party's hashed set
            hash_key: Shared hash key
            
        Returns:
            Hashed intersection
        """
        my_hashed_set = self.hash_set(my_set, hash_key)
        intersection = self.compute_intersection(my_hashed_set, other_hashed_set)
        return intersection
    
    def map_intersection_to_original(self, intersection: Set[bytes], 
                                    original_set: Set[Any], 
                                    hash_key: bytes) -> Set[Any]:
        """
        Map hashed intersection back to original elements.
        
        Args:
            intersection: Hashed intersection
            original_set: Original input set
            hash_key: Hash key used
            
        Returns:
            Original elements that were in intersection
        """
        result = set()
        for element in original_set:
            # Hash element
            if isinstance(element, str):
                element_bytes = element.encode('utf-8')
            elif isinstance(element, int):
                element_bytes = str(element).encode('utf-8')
            elif isinstance(element, bytes):
                element_bytes = element
            else:
                element_bytes = str(element).encode('utf-8')
            
            hashed = hmac.new(hash_key, element_bytes, hashlib.sha256).digest()
            
            if hashed in intersection:
                result.add(element)
        
        return result


class SecureComparison:
    """
    Secure comparison protocols for MPC.
    
    Allows parties to compare values without revealing them.
    """
    
    def __init__(self):
        """Initialize secure comparison protocol."""
        self.sharing = AdditiveSecretSharing()
    
    def compare_greater_than(self, share_a: int, share_b: int, 
                            threshold: int) -> bool:
        """
        Securely compare if reconstructed value is greater than threshold.
        
        Note: In real MPC, this would involve interaction between parties.
        This is a simplified version for demonstration.
        
        Args:
            share_a: Share of value A
            share_b: Share of value B (from another party)
            threshold: Public threshold
            
        Returns:
            True if A > threshold
        """
        reconstructed = self.sharing.reconstruct_secret([share_a, share_b])
        return reconstructed > threshold
    
    def millionaires_problem(self, my_wealth: int, num_parties: int, 
                            party_id: int) -> Tuple[List[int], str]:
        """
        Yao's Millionaires' Problem: compare wealth without revealing amounts.
        
        Args:
            my_wealth: This party's wealth
            num_parties: Total number of parties
            party_id: This party's ID (0-indexed)
            
        Returns:
            Tuple of (shares, computation_id)
        """
        computation_id = secrets.token_hex(16)
        shares = self.sharing.share_secret(my_wealth, num_parties)
        return shares, computation_id


class SecureAggregation:
    """
    Secure aggregation for federated learning and privacy-preserving analytics.
    
    Allows multiple parties to compute aggregate statistics (sum, mean, count)
    without revealing individual contributions.
    """
    
    def __init__(self):
        """Initialize secure aggregation protocol."""
        self.sharing = AdditiveSecretSharing()
        self.participants: Dict[str, Dict[str, Any]] = {}
    
    def register_participant(self, participant_id: str, public_key: bytes = None):
        """
        Register a participant for aggregation.
        
        Args:
            participant_id: Unique participant identifier
            public_key: Optional public key for the participant
        """
        self.participants[participant_id] = {
            'id': participant_id,
            'public_key': public_key or os.urandom(32),
            'shares': {}
        }
    
    def contribute_value(self, participant_id: str, value: int, 
                        computation_id: str) -> List[int]:
        """
        Participant contributes a private value to aggregation.
        
        Args:
            participant_id: Participant's ID
            value: Private value to contribute
            computation_id: Computation session ID
            
        Returns:
            List of shares (to be distributed to all participants)
        """
        if participant_id not in self.participants:
            raise ValueError(f"Unknown participant: {participant_id}")
        
        num_parties = len(self.participants)
        shares = self.sharing.share_secret(value, num_parties)
        
        # Store shares for this computation
        self.participants[participant_id]['shares'][computation_id] = shares
        
        return shares
    
    def aggregate_shares(self, computation_id: str, 
                        shares_from_all: List[List[int]]) -> int:
        """
        Aggregate shares from all participants.
        
        Args:
            computation_id: Computation session ID
            shares_from_all: List of share lists from all participants
            
        Returns:
            Aggregated sum
        """
        if not shares_from_all:
            return 0
        
        num_parties = len(shares_from_all)
        aggregated_shares = []
        
        # For each party position, sum all the shares
        for party_idx in range(num_parties):
            party_sum = sum(shares[party_idx] for shares in shares_from_all)
            aggregated_shares.append(party_sum)
        
        # Reconstruct the total sum
        return self.sharing.reconstruct_secret(aggregated_shares)
    
    def compute_average(self, computation_id: str, 
                       shares_from_all: List[List[int]]) -> float:
        """
        Compute average from aggregated shares.
        
        Args:
            computation_id: Computation session ID
            shares_from_all: List of share lists from all participants
            
        Returns:
            Average value
        """
        total = self.aggregate_shares(computation_id, shares_from_all)
        count = len(shares_from_all)
        return total / count if count > 0 else 0.0


class SecureMultiPartyComputation:
    """
    Main MPC coordinator supporting multiple protocols.
    
    Provides high-level interface for secure multi-party computations:
    - Private sum computation
    - Set intersection
    - Secure comparisons
    - Aggregation
    """
    
    def __init__(self):
        """Initialize MPC system."""
        self.additive_sharing = AdditiveSecretSharing()
        self.psi = PrivateSetIntersection()
        self.comparison = SecureComparison()
        self.aggregation = SecureAggregation()
        self.active_computations: Dict[str, Dict[str, Any]] = {}
    
    def compute_private_sum(self, private_inputs: List[int]) -> int:
        """
        Compute sum of private inputs from multiple parties.
        
        Each party provides their private input, and the sum is computed
        without revealing individual inputs.
        
        Args:
            private_inputs: List of private integers from each party
            
        Returns:
            Sum of all private inputs
        """
        if len(private_inputs) < 2:
            raise ValueError("Need at least 2 parties for MPC")
        
        computation_id = secrets.token_hex(16)
        
        # Each party creates shares of their input
        all_shares = []
        for private_input in private_inputs:
            shares = self.additive_sharing.share_secret(
                private_input, 
                len(private_inputs)
            )
            all_shares.append(shares)
        
        # Aggregate all shares at each party position
        aggregated_shares = []
        for party_idx in range(len(private_inputs)):
            party_sum = sum(shares[party_idx] for shares in all_shares)
            aggregated_shares.append(party_sum)
        
        # Reconstruct the sum
        result = self.additive_sharing.reconstruct_secret(aggregated_shares)
        
        # Store computation
        self.active_computations[computation_id] = {
            'protocol': MPCProtocolType.ADDITIVE_SECRET_SHARING,
            'num_parties': len(private_inputs),
            'result': result
        }
        
        return result
    
    def compute_private_intersection(self, set_a: Set[Any], set_b: Set[Any]) -> Set[Any]:
        """
        Compute intersection of two private sets.
        
        Finds common elements between two sets without revealing
        non-intersecting elements to either party.
        
        Args:
            set_a: First party's private set
            set_b: Second party's private set
            
        Returns:
            Intersection of both sets
        """
        computation_id = secrets.token_hex(16)
        
        # Setup protocol
        hash_key = self.psi.setup_protocol()
        
        # Both parties hash their sets
        hashed_set_a = self.psi.hash_set(set_a, hash_key)
        hashed_set_b = self.psi.hash_set(set_b, hash_key)
        
        # Compute intersection on hashed sets
        hashed_intersection = self.psi.compute_intersection(hashed_set_a, hashed_set_b)
        
        # Map back to original elements (both parties can do this)
        intersection_a = self.psi.map_intersection_to_original(
            hashed_intersection, set_a, hash_key
        )
        intersection_b = self.psi.map_intersection_to_original(
            hashed_intersection, set_b, hash_key
        )
        
        # Verify both got same intersection
        assert intersection_a == intersection_b, "Intersection mismatch"
        
        # Store computation
        self.active_computations[computation_id] = {
            'protocol': MPCProtocolType.PRIVATE_SET_INTERSECTION,
            'num_parties': 2,
            'result': intersection_a,
            'set_sizes': [len(set_a), len(set_b)]
        }
        
        return intersection_a
    
    def secure_average(self, private_values: List[int]) -> float:
        """
        Compute average of private values securely.
        
        Args:
            private_values: List of private integers from each party
            
        Returns:
            Average of all values
        """
        total_sum = self.compute_private_sum(private_values)
        return total_sum / len(private_values) if private_values else 0.0
    
    def secure_voting(self, votes: List[int], candidates: List[str]) -> Dict[str, int]:
        """
        Conduct secure voting where vote counts are public but individual votes are private.
        
        Args:
            votes: List of candidate indices (one per voter)
            candidates: List of candidate names
            
        Returns:
            Dictionary mapping candidate names to vote counts
        """
        computation_id = secrets.token_hex(16)
        
        # Count votes for each candidate
        vote_counts = {candidate: 0 for candidate in candidates}
        
        # For each candidate, compute private sum of votes
        for candidate_idx, candidate in enumerate(candidates):
            # Create binary indicators (1 if voted for this candidate, 0 otherwise)
            indicators = [1 if vote == candidate_idx else 0 for vote in votes]
            
            # Compute private sum
            count = self.compute_private_sum(indicators)
            vote_counts[candidate] = count
        
        # Store computation
        self.active_computations[computation_id] = {
            'protocol': MPCProtocolType.SECURE_AGGREGATION,
            'num_parties': len(votes),
            'result': vote_counts,
            'candidates': candidates
        }
        
        return vote_counts
    
    def get_computation_info(self, computation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a computation.
        
        Args:
            computation_id: Computation identifier
            
        Returns:
            Computation information or None if not found
        """
        return self.active_computations.get(computation_id)
    
    def list_computations(self) -> List[str]:
        """
        List all active computation IDs.
        
        Returns:
            List of computation IDs
        """
        return list(self.active_computations.keys())


# Convenience functions for common use cases
def private_sum(*values: int) -> int:
    """
    Compute private sum of values.
    
    Args:
        *values: Variable number of integer values
        
    Returns:
        Sum of all values
    """
    mpc = SecureMultiPartyComputation()
    return mpc.compute_private_sum(list(values))


def private_intersection(set_a: Set[Any], set_b: Set[Any]) -> Set[Any]:
    """
    Compute private set intersection.
    
    Args:
        set_a: First set
        set_b: Second set
        
    Returns:
        Intersection of sets
    """
    mpc = SecureMultiPartyComputation()
    return mpc.compute_private_intersection(set_a, set_b)


def private_average(*values: int) -> float:
    """
    Compute private average of values.
    
    Args:
        *values: Variable number of integer values
        
    Returns:
        Average of all values
    """
    mpc = SecureMultiPartyComputation()
    return mpc.secure_average(list(values))
