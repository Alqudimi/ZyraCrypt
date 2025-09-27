"""
Secure Enclave and Multi-Party Computation (MPC) Abstraction

This module provides abstractions for secure enclaves (HSMs, TPMs, Secure Elements)
and multi-party computation protocols for sensitive cryptographic operations.
"""

import os
import json
import time
import secrets
import hashlib
from typing import Dict, List, Optional, Tuple, Any, Protocol
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod

# Side-channel protection
from .side_channel_protection import SideChannelGuard, secure_memory


class EnclaveType(Enum):
    """Types of secure enclaves."""
    SOFTWARE_SIMULATION = "software_simulation"  # Development only
    PKCS11_HSM = "pkcs11_hsm"                   # PKCS#11 Hardware Security Module
    TPM_2_0 = "tpm_2_0"                         # Trusted Platform Module 2.0
    INTEL_SGX = "intel_sgx"                     # Intel Software Guard Extensions
    ARM_TRUSTZONE = "arm_trustzone"             # ARM TrustZone
    AWS_NITRO = "aws_nitro"                     # AWS Nitro Enclaves
    AZURE_CONFIDENTIAL = "azure_confidential"   # Azure Confidential Computing
    GCP_CONFIDENTIAL = "gcp_confidential"       # Google Cloud Confidential Computing


class MPCProtocol(Enum):
    """Multi-party computation protocols."""
    SECRET_SHARING = "secret_sharing"           # Shamir's Secret Sharing
    GARBLED_CIRCUITS = "garbled_circuits"       # Yao's Garbled Circuits
    GMW_PROTOCOL = "gmw_protocol"              # Goldreich-Micali-Wigderson
    BGW_PROTOCOL = "bgw_protocol"              # Ben-Or-Goldwasser-Wigderson
    SPDZ = "spdz"                              # SPDZ protocol
    ABY3 = "aby3"                              # ABY3 three-party protocol


@dataclass
class EnclaveCapabilities:
    """Capabilities of a secure enclave."""
    can_generate_keys: bool = True
    can_sign: bool = True
    can_encrypt: bool = True
    can_decrypt: bool = True
    can_derive_keys: bool = True
    can_attest: bool = False
    can_seal_unseal: bool = False
    supports_remote_attestation: bool = False
    max_key_size: Optional[int] = None
    supported_algorithms: List[str] = None
    
    def __post_init__(self):
        if self.supported_algorithms is None:
            self.supported_algorithms = []


@dataclass
class AttestationReport:
    """Attestation report from secure enclave."""
    enclave_id: str
    enclave_type: EnclaveType
    report_data: bytes
    signature: bytes
    timestamp: float
    nonce: bytes
    platform_info: Dict[str, Any]
    verified: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'enclave_id': self.enclave_id,
            'enclave_type': self.enclave_type.value,
            'report_data': self.report_data.hex(),
            'signature': self.signature.hex(),
            'timestamp': self.timestamp,
            'nonce': self.nonce.hex(),
            'platform_info': self.platform_info,
            'verified': self.verified
        }


class SecureEnclaveProvider(ABC):
    """Abstract base class for secure enclave providers."""
    
    @abstractmethod
    def get_capabilities(self) -> EnclaveCapabilities:
        """Get enclave capabilities."""
        pass
    
    @abstractmethod
    def generate_key(self, algorithm: str, key_size: int, 
                    key_id: Optional[str] = None) -> str:
        """Generate a key inside the enclave."""
        pass
    
    @abstractmethod
    def sign(self, key_id: str, data: bytes, algorithm: str = "ECDSA") -> bytes:
        """Sign data using enclave-protected key."""
        pass
    
    @abstractmethod
    def encrypt(self, key_id: str, plaintext: bytes, 
               algorithm: str = "AES-GCM") -> bytes:
        """Encrypt data using enclave-protected key."""
        pass
    
    @abstractmethod
    def decrypt(self, key_id: str, ciphertext: bytes,
               algorithm: str = "AES-GCM") -> bytes:
        """Decrypt data using enclave-protected key."""
        pass
    
    @abstractmethod
    def derive_key(self, master_key_id: str, derivation_data: bytes,
                  algorithm: str = "HKDF") -> str:
        """Derive a new key from a master key."""
        pass
    
    @abstractmethod
    def attest(self, nonce: bytes, user_data: Optional[bytes] = None) -> AttestationReport:
        """Generate attestation report."""
        pass
    
    @abstractmethod
    def seal_data(self, data: bytes, policy: Optional[Dict[str, Any]] = None) -> bytes:
        """Seal data to this enclave instance."""
        pass
    
    @abstractmethod
    def unseal_data(self, sealed_data: bytes) -> bytes:
        """Unseal data sealed to this enclave."""
        pass
    
    @abstractmethod
    def delete_key(self, key_id: str) -> bool:
        """Delete a key from the enclave."""
        pass


class SoftwareEnclaveSimulator(SecureEnclaveProvider):
    """
    Software simulation of secure enclave for development purposes.
    WARNING: This is NOT secure and should only be used for development!
    """
    
    def __init__(self, enclave_id: str = None):
        self.enclave_id = enclave_id or f"sim-enclave-{secrets.token_hex(8)}"
        self.keys: Dict[str, Dict[str, Any]] = {}
        self.sealed_data: Dict[str, bytes] = {}
        self.capabilities = EnclaveCapabilities(
            can_generate_keys=True,
            can_sign=True,
            can_encrypt=True,
            can_decrypt=True,
            can_derive_keys=True,
            can_attest=True,
            can_seal_unseal=True,
            supports_remote_attestation=False,
            max_key_size=4096,
            supported_algorithms=["AES-256", "RSA-2048", "ECDSA-P256", "Ed25519"]
        )
    
    def get_capabilities(self) -> EnclaveCapabilities:
        """Get simulated enclave capabilities."""
        return self.capabilities
    
    def generate_key(self, algorithm: str, key_size: int,
                    key_id: Optional[str] = None) -> str:
        """Generate a simulated key."""
        if key_id is None:
            key_id = f"key-{secrets.token_hex(16)}"
        
        # Generate random key material (not cryptographically sound)
        key_material = secrets.token_bytes(key_size // 8)
        
        self.keys[key_id] = {
            'algorithm': algorithm,
            'key_size': key_size,
            'key_material': key_material,
            'created_at': time.time(),
            'usage_count': 0
        }
        
        return key_id
    
    @SideChannelGuard(protect_timing=True)
    def sign(self, key_id: str, data: bytes, algorithm: str = "ECDSA") -> bytes:
        """Simulate signing operation."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key_info = self.keys[key_id]
        key_info['usage_count'] += 1
        
        # Simulate signature generation (not cryptographically sound)
        signature_input = key_info['key_material'] + data + algorithm.encode()
        return hashlib.sha256(signature_input).digest()
    
    @SideChannelGuard(protect_timing=True)
    def encrypt(self, key_id: str, plaintext: bytes,
               algorithm: str = "AES-GCM") -> bytes:
        """Simulate encryption operation."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key_info = self.keys[key_id]
        key_info['usage_count'] += 1
        
        # Simulate encryption (not cryptographically sound)
        nonce = secrets.token_bytes(12)
        # Simple XOR with key hash for simulation
        key_hash = hashlib.sha256(key_info['key_material']).digest()
        
        ciphertext = bytearray()
        for i, byte in enumerate(plaintext):
            ciphertext.append(byte ^ key_hash[i % len(key_hash)])
        
        return nonce + bytes(ciphertext)
    
    @SideChannelGuard(protect_timing=True)
    def decrypt(self, key_id: str, ciphertext: bytes,
               algorithm: str = "AES-GCM") -> bytes:
        """Simulate decryption operation."""
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        
        key_info = self.keys[key_id]
        key_info['usage_count'] += 1
        
        # Extract nonce and encrypted data
        nonce = ciphertext[:12]
        encrypted_data = ciphertext[12:]
        
        # Simulate decryption (reverse of encryption simulation)
        key_hash = hashlib.sha256(key_info['key_material']).digest()
        
        plaintext = bytearray()
        for i, byte in enumerate(encrypted_data):
            plaintext.append(byte ^ key_hash[i % len(key_hash)])
        
        return bytes(plaintext)
    
    def derive_key(self, master_key_id: str, derivation_data: bytes,
                  algorithm: str = "HKDF") -> str:
        """Simulate key derivation."""
        if master_key_id not in self.keys:
            raise ValueError(f"Master key not found: {master_key_id}")
        
        master_key = self.keys[master_key_id]
        
        # Derive new key material
        derived_material = hashlib.sha256(
            master_key['key_material'] + derivation_data
        ).digest()
        
        # Create new key entry
        new_key_id = f"derived-{secrets.token_hex(16)}"
        self.keys[new_key_id] = {
            'algorithm': algorithm,
            'key_size': len(derived_material) * 8,
            'key_material': derived_material,
            'created_at': time.time(),
            'usage_count': 0,
            'derived_from': master_key_id
        }
        
        return new_key_id
    
    def attest(self, nonce: bytes, user_data: Optional[bytes] = None) -> AttestationReport:
        """Generate simulated attestation report."""
        report_data = nonce
        if user_data:
            report_data += user_data
        
        # Simulate attestation signature
        attestation_key = hashlib.sha256(self.enclave_id.encode()).digest()
        signature = hashlib.hmac.new(
            attestation_key, report_data, hashlib.sha256
        ).digest()
        
        return AttestationReport(
            enclave_id=self.enclave_id,
            enclave_type=EnclaveType.SOFTWARE_SIMULATION,
            report_data=report_data,
            signature=signature,
            timestamp=time.time(),
            nonce=nonce,
            platform_info={'simulator': True, 'version': '1.0'},
            verified=False  # Simulation cannot be truly verified
        )
    
    def seal_data(self, data: bytes, policy: Optional[Dict[str, Any]] = None) -> bytes:
        """Simulate sealing data to enclave."""
        seal_id = secrets.token_hex(16)
        
        # Simulate sealing with enclave-specific key
        sealing_key = hashlib.sha256(
            self.enclave_id.encode() + b'SEALING_KEY'
        ).digest()
        
        # Simple encryption simulation
        sealed = bytearray()
        for i, byte in enumerate(data):
            sealed.append(byte ^ sealing_key[i % len(sealing_key)])
        
        sealed_blob = seal_id.encode() + bytes(sealed)
        self.sealed_data[seal_id] = data  # Store for unsealing
        
        return sealed_blob
    
    def unseal_data(self, sealed_data: bytes) -> bytes:
        """Simulate unsealing data."""
        seal_id = sealed_data[:32].decode()  # 16 bytes hex = 32 chars
        encrypted_data = sealed_data[32:]
        
        if seal_id not in self.sealed_data:
            raise ValueError("Cannot unseal data - not sealed by this enclave")
        
        return self.sealed_data[seal_id]
    
    def delete_key(self, key_id: str) -> bool:
        """Delete a simulated key."""
        if key_id in self.keys:
            del self.keys[key_id]
            return True
        return False


class MPCParticipant:
    """Participant in a multi-party computation protocol."""
    
    def __init__(self, participant_id: str, enclave_provider: SecureEnclaveProvider):
        self.participant_id = participant_id
        self.enclave = enclave_provider
        self.shared_secrets: Dict[str, Any] = {}
        self.computation_state: Dict[str, Any] = {}
    
    def generate_secret_share(self, secret_id: str, secret_value: int,
                            threshold: int, total_participants: int) -> List[Tuple[int, int]]:
        """Generate secret shares for Shamir's secret sharing."""
        from .threshold_multisig import ShamirSecretSharing
        
        shamir = ShamirSecretSharing()
        shares = shamir.split_secret(secret_value, threshold, total_participants)
        
        self.shared_secrets[secret_id] = {
            'threshold': threshold,
            'total_participants': total_participants,
            'my_share': shares[0] if shares else None  # In practice, distribute properly
        }
        
        return shares
    
    def receive_secret_share(self, secret_id: str, share: Tuple[int, int]):
        """Receive a secret share from another participant."""
        if secret_id not in self.shared_secrets:
            self.shared_secrets[secret_id] = {'received_shares': []}
        
        self.shared_secrets[secret_id]['received_shares'] = (
            self.shared_secrets[secret_id].get('received_shares', [])
        )
        self.shared_secrets[secret_id]['received_shares'].append(share)
    
    def compute_on_shares(self, computation_id: str, operation: str, 
                         operand_ids: List[str]) -> Any:
        """Perform computation on secret shares."""
        # This is a simplified MPC computation simulation
        # Real MPC protocols would be much more complex
        
        if operation == "add":
            # Addition of secret shares
            result_shares = []
            for operand_id in operand_ids:
                if operand_id in self.shared_secrets:
                    shares = self.shared_secrets[operand_id].get('received_shares', [])
                    result_shares.extend(shares)
            
            self.computation_state[computation_id] = {
                'operation': operation,
                'result_shares': result_shares,
                'timestamp': time.time()
            }
            
            return len(result_shares)
        
        elif operation == "multiply":
            # Multiplication of secret shares (more complex in real MPC)
            # This is just a placeholder
            return self.compute_on_shares(computation_id, "add", operand_ids)
        
        else:
            raise ValueError(f"Unsupported MPC operation: {operation}")
    
    def reveal_result(self, computation_id: str, threshold: int) -> Optional[int]:
        """Reveal the result of MPC computation."""
        if computation_id not in self.computation_state:
            return None
        
        computation = self.computation_state[computation_id]
        shares = computation.get('result_shares', [])
        
        if len(shares) < threshold:
            return None
        
        # Reconstruct secret using Shamir's secret sharing
        from .threshold_multisig import ShamirSecretSharing
        
        shamir = ShamirSecretSharing()
        try:
            result = shamir.reconstruct_secret(shares[:threshold])
            return result
        except Exception:
            return None


class SecureEnclaveManager:
    """Manager for secure enclave operations and MPC protocols."""
    
    def __init__(self):
        self.enclaves: Dict[str, SecureEnclaveProvider] = {}
        self.mpc_participants: Dict[str, MPCParticipant] = {}
        self.active_computations: Dict[str, Dict[str, Any]] = {}
    
    def register_enclave(self, name: str, provider: SecureEnclaveProvider):
        """Register a secure enclave provider."""
        self.enclaves[name] = provider
    
    def get_enclave(self, name: str) -> Optional[SecureEnclaveProvider]:
        """Get a registered enclave provider."""
        return self.enclaves.get(name)
    
    def create_development_enclave(self, name: str = "dev_enclave") -> str:
        """Create a development enclave for testing."""
        dev_enclave = SoftwareEnclaveSimulator()
        self.enclaves[name] = dev_enclave
        return name
    
    def secure_key_generation(self, enclave_name: str, algorithm: str, 
                            key_size: int) -> Optional[str]:
        """Generate a key in a secure enclave."""
        enclave = self.get_enclave(enclave_name)
        if not enclave:
            return None
        
        return enclave.generate_key(algorithm, key_size)
    
    def secure_sign(self, enclave_name: str, key_id: str, data: bytes,
                   algorithm: str = "ECDSA") -> Optional[bytes]:
        """Sign data using enclave-protected key."""
        enclave = self.get_enclave(enclave_name)
        if not enclave:
            return None
        
        return enclave.sign(key_id, data, algorithm)
    
    def verify_attestation(self, attestation_report: AttestationReport,
                          expected_enclave_type: EnclaveType) -> bool:
        """Verify an attestation report."""
        if attestation_report.enclave_type != expected_enclave_type:
            return False
        
        # In a real implementation, this would verify the attestation signature
        # against known root certificates and check the platform information
        
        # For simulation, we just check basic fields
        current_time = time.time()
        if abs(current_time - attestation_report.timestamp) > 300:  # 5 minutes
            return False
        
        attestation_report.verified = True
        return True
    
    def start_mpc_computation(self, computation_id: str, participants: List[str],
                            threshold: int, protocol: MPCProtocol = MPCProtocol.SECRET_SHARING) -> bool:
        """Start a multi-party computation."""
        if computation_id in self.active_computations:
            return False
        
        self.active_computations[computation_id] = {
            'participants': participants,
            'threshold': threshold,
            'protocol': protocol,
            'started_at': time.time(),
            'status': 'initialized'
        }
        
        return True
    
    def add_mpc_participant(self, participant_id: str, 
                          enclave_name: str) -> MPCParticipant:
        """Add a participant to MPC operations."""
        enclave = self.get_enclave(enclave_name)
        if not enclave:
            raise ValueError(f"Unknown enclave: {enclave_name}")
        
        participant = MPCParticipant(participant_id, enclave)
        self.mpc_participants[participant_id] = participant
        return participant
    
    def list_enclaves(self) -> Dict[str, EnclaveCapabilities]:
        """List all registered enclaves and their capabilities."""
        return {
            name: provider.get_capabilities() 
            for name, provider in self.enclaves.items()
        }
    
    def get_computation_status(self, computation_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of an MPC computation."""
        return self.active_computations.get(computation_id)


# Global secure enclave manager instance
enclave_manager = SecureEnclaveManager()