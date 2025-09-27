"""
Secure Multi-Party Computation (MPC) and Secure Enclaves
Enables sensitive private key operations without key exposure
Implements secure computation protocols for distributed cryptography
"""

import os
import json
import time
import hashlib
import struct
import secrets
import threading
from typing import Dict, List, Optional, Tuple, Any, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod

# Core cryptography
import nacl.secret
import nacl.utils
import nacl.encoding
from cryptography.hazmat.primitives import hashes, constant_time, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Mathematical operations
from functools import reduce
from operator import xor


class MPCProtocol(Enum):
    """Supported MPC protocols"""
    SECRET_SHARING = "secret_sharing"
    GARBLED_CIRCUITS = "garbled_circuits"
    HOMOMORPHIC_ENCRYPTION = "homomorphic_encryption"
    OBLIVIOUS_TRANSFER = "oblivious_transfer"


class EnclaveType(Enum):
    """Types of secure enclaves"""
    SOFTWARE_ENCLAVE = "software_enclave"      # Software-based isolation
    SECURE_MEMORY = "secure_memory"           # Protected memory regions
    HSM_ENCLAVE = "hsm_enclave"              # Hardware Security Module
    TEE_ENCLAVE = "tee_enclave"              # Trusted Execution Environment


class ComputationStatus(Enum):
    """Status of secure computation"""
    INITIALIZED = "initialized"
    PARTICIPANTS_JOINING = "participants_joining"
    COMPUTING = "computing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SecretShare:
    """Secret share for MPC"""
    party_id: str
    share_value: bytes
    share_index: int
    total_shares: int
    computation_id: str
    timestamp: float


@dataclass
class MPCParticipant:
    """MPC participant information"""
    participant_id: str
    public_key: bytes
    endpoint: Optional[str] = None
    capabilities: List[MPCProtocol] = None
    trust_level: int = 0  # 0-100 trust score


@dataclass
class SecureComputation:
    """Secure computation session"""
    computation_id: str
    protocol: MPCProtocol
    participants: List[MPCParticipant]
    function_spec: Dict[str, Any]
    status: ComputationStatus
    created_at: float
    result: Optional[bytes] = None
    error_message: Optional[str] = None


class SecureEnclave:
    """
    Software-based secure enclave for sensitive operations
    Provides memory protection and execution isolation
    """
    
    def __init__(self, enclave_type: EnclaveType = EnclaveType.SOFTWARE_ENCLAVE):
        """Initialize secure enclave"""
        self.enclave_type = enclave_type
        self.enclave_id = hashlib.sha256(
            os.urandom(32) + str(time.time()).encode()
        ).hexdigest()[:16]
        
        # Secure memory for sensitive data
        self._secure_memory: Dict[str, bytes] = {}
        self._access_log: List[Tuple[float, str, str]] = []
        self._is_sealed = False
        
        # Attestation and integrity
        self._measurement = self._calculate_enclave_measurement()
        self._lock = threading.RLock()
    
    def _calculate_enclave_measurement(self) -> bytes:
        """Calculate enclave measurement for attestation"""
        # In a real implementation, this would include code hash, etc.
        measurement_data = f"SecureEnclave-{self.enclave_id}-v1.0".encode()
        return hashlib.sha256(measurement_data).digest()
    
    def store_secret(self, key: str, value: bytes) -> bool:
        """
        Store secret data in secure memory
        """
        with self._lock:
            if self._is_sealed:
                return False
            
            # Encrypt value before storing
            encryption_key = hashlib.sha256(
                self._measurement + key.encode()
            ).digest()
            
            box = nacl.secret.SecretBox(encryption_key)
            encrypted_value = box.encrypt(value)
            
            self._secure_memory[key] = encrypted_value
            self._log_access("STORE", key)
            
            return True
    
    def retrieve_secret(self, key: str) -> Optional[bytes]:
        """
        Retrieve secret data from secure memory
        """
        with self._lock:
            if key not in self._secure_memory:
                return None
            
            # Decrypt value
            encryption_key = hashlib.sha256(
                self._measurement + key.encode()
            ).digest()
            
            try:
                box = nacl.secret.SecretBox(encryption_key)
                decrypted_value = box.decrypt(self._secure_memory[key])
                
                self._log_access("RETRIEVE", key)
                return decrypted_value
            except Exception:
                return None
    
    def secure_computation(self, function: Callable[[bytes], bytes], 
                          input_key: str, output_key: str) -> bool:
        """
        Perform secure computation within enclave
        """
        with self._lock:
            input_data = self.retrieve_secret(input_key)
            if input_data is None:
                return False
            
            try:
                # Perform computation
                result = function(input_data)
                
                # Store result
                success = self.store_secret(output_key, result)
                self._log_access("COMPUTE", f"{input_key}->{output_key}")
                
                return success
            except Exception:
                return False
    
    def seal_enclave(self):
        """
        Seal enclave to prevent further modifications
        """
        with self._lock:
            self._is_sealed = True
            self._log_access("SEAL", "enclave")
    
    def get_attestation(self) -> Dict[str, Any]:
        """
        Get enclave attestation for remote verification
        """
        return {
            'enclave_id': self.enclave_id,
            'enclave_type': self.enclave_type.value,
            'measurement': nacl.encoding.Base64Encoder.encode(self._measurement).decode(),
            'is_sealed': self._is_sealed,
            'created_at': time.time(),
            'access_count': len(self._access_log)
        }
    
    def _log_access(self, operation: str, target: str):
        """Log access for audit purposes"""
        self._access_log.append((time.time(), operation, target))
        
        # Keep only recent logs
        if len(self._access_log) > 1000:
            self._access_log = self._access_log[-500:]
    
    def clear_secrets(self):
        """
        Securely clear all stored secrets
        """
        with self._lock:
            # Overwrite memory with random data before deletion
            for key in list(self._secure_memory.keys()):
                random_data = os.urandom(len(self._secure_memory[key]))
                self._secure_memory[key] = random_data
            
            self._secure_memory.clear()
            self._log_access("CLEAR", "all_secrets")


class MPCCoordinator:
    """
    Coordinator for multi-party computation protocols
    """
    
    def __init__(self):
        """Initialize MPC coordinator"""
        self.active_computations: Dict[str, SecureComputation] = {}
        self.registered_participants: Dict[str, MPCParticipant] = {}
        self.enclave = SecureEnclave()
    
    def register_participant(self, participant: MPCParticipant):
        """
        Register a participant for MPC
        """
        self.registered_participants[participant.participant_id] = participant
    
    def create_computation(self, protocol: MPCProtocol, 
                          function_spec: Dict[str, Any],
                          required_participants: List[str]) -> str:
        """
        Create a new secure computation session
        """
        computation_id = hashlib.sha256(
            json.dumps(function_spec, sort_keys=True).encode() + 
            str(time.time()).encode()
        ).hexdigest()[:16]
        
        # Get participant objects
        participants = []
        for participant_id in required_participants:
            if participant_id in self.registered_participants:
                participants.append(self.registered_participants[participant_id])
        
        if len(participants) != len(required_participants):
            raise ValueError("Some required participants not registered")
        
        computation = SecureComputation(
            computation_id=computation_id,
            protocol=protocol,
            participants=participants,
            function_spec=function_spec,
            status=ComputationStatus.INITIALIZED,
            created_at=time.time()
        )
        
        self.active_computations[computation_id] = computation
        return computation_id
    
    def submit_secret_share(self, computation_id: str, share: SecretShare) -> bool:
        """
        Submit a secret share for computation
        """
        if computation_id not in self.active_computations:
            return False
        
        computation = self.active_computations[computation_id]
        
        # Verify participant is authorized
        participant_ids = [p.participant_id for p in computation.participants]
        if share.party_id not in participant_ids:
            return False
        
        # Store share in enclave
        share_key = f"share_{computation_id}_{share.party_id}_{share.share_index}"
        success = self.enclave.store_secret(share_key, share.share_value)
        
        if success:
            # Check if we have all shares needed
            self._check_computation_ready(computation_id)
        
        return success
    
    def execute_secure_function(self, computation_id: str) -> bool:
        """
        Execute the secure function using MPC
        """
        if computation_id not in self.active_computations:
            return False
        
        computation = self.active_computations[computation_id]
        
        if computation.status != ComputationStatus.PARTICIPANTS_JOINING:
            return False
        
        computation.status = ComputationStatus.COMPUTING
        
        try:
            if computation.protocol == MPCProtocol.SECRET_SHARING:
                result = self._execute_secret_sharing_computation(computation)
            else:
                raise ValueError(f"Unsupported protocol: {computation.protocol}")
            
            if result:
                computation.result = result
                computation.status = ComputationStatus.COMPLETED
                return True
            else:
                computation.status = ComputationStatus.FAILED
                return False
                
        except Exception as e:
            computation.error_message = str(e)
            computation.status = ComputationStatus.FAILED
            return False
    
    def _execute_secret_sharing_computation(self, computation: SecureComputation) -> Optional[bytes]:
        """
        Execute computation using secret sharing
        """
        function_name = computation.function_spec.get('function', 'unknown')
        
        if function_name == 'threshold_signature':
            return self._execute_threshold_signature(computation)
        elif function_name == 'secret_reconstruction':
            return self._execute_secret_reconstruction(computation)
        else:
            return None
    
    def _execute_threshold_signature(self, computation: SecureComputation) -> Optional[bytes]:
        """
        Execute threshold signature computation
        """
        # Collect all shares for this computation
        shares = []
        for participant in computation.participants:
            for share_index in range(1, len(computation.participants) + 1):
                share_key = f"share_{computation.computation_id}_{participant.participant_id}_{share_index}"
                share_data = self.enclave.retrieve_secret(share_key)
                if share_data:
                    shares.append(share_data)
        
        if not shares:
            return None
        
        # Simple threshold signature computation (placeholder)
        message = computation.function_spec.get('message', b'').encode() if isinstance(
            computation.function_spec.get('message', b''), str
        ) else computation.function_spec.get('message', b'')
        
        # Combine shares and message
        combined_data = b''.join(shares) + message
        signature = hashlib.sha256(combined_data).digest()
        
        return signature
    
    def _execute_secret_reconstruction(self, computation: SecureComputation) -> Optional[bytes]:
        """
        Execute secret reconstruction from shares
        """
        threshold = computation.function_spec.get('threshold', 2)
        
        # Collect shares
        shares = []
        for participant in computation.participants:
            for share_index in range(1, len(computation.participants) + 1):
                share_key = f"share_{computation.computation_id}_{participant.participant_id}_{share_index}"
                share_data = self.enclave.retrieve_secret(share_key)
                if share_data:
                    shares.append(share_data)
                
                if len(shares) >= threshold:
                    break
            
            if len(shares) >= threshold:
                break
        
        if len(shares) < threshold:
            return None
        
        # Simple secret reconstruction (XOR for demonstration)
        reconstructed_secret = shares[0]
        for share in shares[1:threshold]:
            reconstructed_secret = bytes(a ^ b for a, b in zip(reconstructed_secret, share))
        
        return reconstructed_secret
    
    def _check_computation_ready(self, computation_id: str):
        """
        Check if computation has all required shares
        """
        computation = self.active_computations[computation_id]
        
        # Simple check - if we have at least one share per participant
        shares_received = 0
        for participant in computation.participants:
            for share_index in range(1, len(computation.participants) + 1):
                share_key = f"share_{computation_id}_{participant.participant_id}_{share_index}"
                if self.enclave.retrieve_secret(share_key) is not None:
                    shares_received += 1
                    break  # Found at least one share for this participant
        
        if shares_received == len(computation.participants):
            computation.status = ComputationStatus.PARTICIPANTS_JOINING
    
    def get_computation_result(self, computation_id: str) -> Optional[bytes]:
        """
        Get result of completed computation
        """
        if computation_id not in self.active_computations:
            return None
        
        computation = self.active_computations[computation_id]
        
        if computation.status == ComputationStatus.COMPLETED:
            return computation.result
        
        return None
    
    def get_computation_status(self, computation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of computation
        """
        if computation_id not in self.active_computations:
            return None
        
        computation = self.active_computations[computation_id]
        
        return {
            'computation_id': computation.computation_id,
            'protocol': computation.protocol.value,
            'status': computation.status.value,
            'participants': [p.participant_id for p in computation.participants],
            'created_at': computation.created_at,
            'has_result': computation.result is not None,
            'error_message': computation.error_message
        }


class SecureKeyGeneration:
    """
    Secure key generation using MPC and enclaves
    """
    
    def __init__(self):
        """Initialize secure key generation"""
        self.mpc_coordinator = MPCCoordinator()
        self.enclave = SecureEnclave()
    
    def distributed_key_generation(self, participants: List[str], 
                                  threshold: int, key_type: str = 'ecdsa') -> Optional[str]:
        """
        Generate cryptographic keys using distributed protocol
        """
        # Register participants
        for participant_id in participants:
            participant = MPCParticipant(
                participant_id=participant_id,
                public_key=os.urandom(32),  # Placeholder
                capabilities=[MPCProtocol.SECRET_SHARING]
            )
            self.mpc_coordinator.register_participant(participant)
        
        # Create computation for key generation
        function_spec = {
            'function': 'key_generation',
            'key_type': key_type,
            'threshold': threshold,
            'participants': participants
        }
        
        computation_id = self.mpc_coordinator.create_computation(
            MPCProtocol.SECRET_SHARING,
            function_spec,
            participants
        )
        
        # Generate key material in enclave
        if key_type == 'ecdsa':
            # Generate ECDSA private key
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            private_value = private_key.private_numbers().private_value
            key_bytes = private_value.to_bytes(32, 'big')
        else:
            # Generate symmetric key
            key_bytes = nacl.utils.random(32)
        
        # Split key into shares
        shares = self._split_key_into_shares(key_bytes, threshold, len(participants))
        
        # Submit shares to computation
        for i, participant_id in enumerate(participants):
            share = SecretShare(
                party_id=participant_id,
                share_value=shares[i],
                share_index=i + 1,
                total_shares=len(participants),
                computation_id=computation_id,
                timestamp=time.time()
            )
            
            self.mpc_coordinator.submit_secret_share(computation_id, share)
        
        return computation_id
    
    def secure_signing(self, computation_id: str, message: bytes, 
                      signing_participants: List[str]) -> Optional[bytes]:
        """
        Perform secure signing using threshold cryptography
        """
        # Create signing computation
        function_spec = {
            'function': 'threshold_signature',
            'message': message,
            'participants': signing_participants
        }
        
        sign_computation_id = self.mpc_coordinator.create_computation(
            MPCProtocol.SECRET_SHARING,
            function_spec,
            signing_participants
        )
        
        # Transfer relevant shares to signing computation
        for participant_id in signing_participants:
            share_key = f"share_{computation_id}_{participant_id}_1"
            share_data = self.enclave.retrieve_secret(share_key)
            
            if share_data:
                sign_share = SecretShare(
                    party_id=participant_id,
                    share_value=share_data,
                    share_index=1,
                    total_shares=len(signing_participants),
                    computation_id=sign_computation_id,
                    timestamp=time.time()
                )
                
                self.mpc_coordinator.submit_secret_share(sign_computation_id, sign_share)
        
        # Execute signing
        success = self.mpc_coordinator.execute_secure_function(sign_computation_id)
        
        if success:
            return self.mpc_coordinator.get_computation_result(sign_computation_id)
        
        return None
    
    def _split_key_into_shares(self, key: bytes, threshold: int, num_shares: int) -> List[bytes]:
        """
        Split key into secret shares (simplified implementation)
        """
        shares = []
        
        # Simple XOR-based sharing for demonstration
        # In production, use proper Shamir's Secret Sharing
        random_shares = [nacl.utils.random(len(key)) for _ in range(num_shares - 1)]
        
        # Calculate last share to maintain XOR property
        last_share = key
        for share in random_shares:
            last_share = bytes(a ^ b for a, b in zip(last_share, share))
        
        shares.extend(random_shares)
        shares.append(last_share)
        
        return shares
    
    def get_key_info(self, computation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about generated key
        """
        status = self.mpc_coordinator.get_computation_status(computation_id)
        if not status:
            return None
        
        return {
            'key_id': computation_id,
            'generation_status': status['status'],
            'participants': status['participants'],
            'created_at': status['created_at'],
            'available_for_signing': status['status'] == 'completed'
        }


# Utility functions for secure operations
def secure_memory_operation(operation: Callable[[], Any], 
                          clear_after: bool = True) -> Any:
    """
    Execute operation in secure memory context
    """
    enclave = SecureEnclave()
    
    try:
        result = operation()
        return result
    finally:
        if clear_after:
            enclave.clear_secrets()


def create_secure_computation_session(participants: List[str], 
                                    protocol: MPCProtocol = MPCProtocol.SECRET_SHARING) -> MPCCoordinator:
    """
    Create a secure computation session
    """
    coordinator = MPCCoordinator()
    
    for participant_id in participants:
        participant = MPCParticipant(
            participant_id=participant_id,
            public_key=nacl.utils.random(32),
            capabilities=[protocol]
        )
        coordinator.register_participant(participant)
    
    return coordinator