
from typing import Union, Tuple
from .algorithm_manager import AlgorithmManager
from .symmetric_encryption import SymmetricEncryption
from .asymmetric_encryption import AsymmetricEncryption
from .plausible_deniability import PlausibleDeniability
try:
    from ..post_quantum_cryptography.post_quantum_cryptography_unit import PostQuantumCryptographyUnit
    PQC_IMPORT_AVAILABLE = True
except ImportError:
    PQC_IMPORT_AVAILABLE = False
import os

class EncryptionFramework:
    def __init__(self):
        self.algo_manager = AlgorithmManager()
        self.symmetric_enc = SymmetricEncryption()
        self.asymmetric_enc = AsymmetricEncryption()
        self.plausible_deniability = PlausibleDeniability()
        # Initialize PQC unit
        if PQC_IMPORT_AVAILABLE:
            try:
                self.pqc_unit = PostQuantumCryptographyUnit()
            except Exception as e:
                print(f"Warning: PQC unit initialization failed: {e}")
                self.pqc_unit = None
        else:
            self.pqc_unit = None

    def encrypt(self, data: bytes, key: bytes, encryption_type: str = "auto", associated_data: bytes | None = None) -> Tuple[str, bytes, bytes, bytes]:
        """Encrypts data using selected algorithm. Returns algorithm name, IV/nonce, ciphertext, and tag (for GCM)."""
        if encryption_type == "auto":
            algo_name = self.algo_manager.select_symmetric_algorithm(len(data))
        elif encryption_type in ["AES-GCM", "ChaCha20"]:
            algo_name = encryption_type
        else:
            raise ValueError("Invalid encryption_type. Must be 'auto', 'AES-GCM', or 'ChaCha20'.")

        if algo_name == "AES-GCM":
            iv, ciphertext, tag = self.symmetric_enc.encrypt_aes_gcm(key, data, associated_data)
            return algo_name, iv, ciphertext, tag
        elif algo_name == "ChaCha20":
            nonce, ciphertext = self.symmetric_enc.encrypt_chacha20_poly1305(key, data, associated_data)
            return algo_name, nonce, ciphertext, b"" # No tag for ChaCha20
        else:
            raise NotImplementedError(f"Encryption algorithm {algo_name} not implemented.")

    def decrypt(self, algo_name: str, key: bytes, iv_nonce: bytes, ciphertext: bytes, tag: bytes = b"", associated_data: bytes | None = None) -> bytes:
        """Decrypts data using the specified algorithm."""
        if algo_name == "AES-GCM":
            return self.symmetric_enc.decrypt_aes_gcm(key, iv_nonce, ciphertext, tag, associated_data)
        elif algo_name == "ChaCha20":
            return self.symmetric_enc.decrypt_chacha20_poly1305(key, iv_nonce, ciphertext, associated_data)
        else:
            raise NotImplementedError(f"Decryption algorithm {algo_name} not implemented.")

    def create_plausible_deniability_layer(self, real_data: bytes, fake_data: bytes, key: bytes) -> bytes:
        """Creates a plausible deniability layer."""
        return self.plausible_deniability.create_hidden_layer(real_data, fake_data, key)

    def reveal_plausible_deniability_layer(self, combined_data: bytes, key: bytes, fake_data_length: int) -> bytes:
        """Reveals the real data from a plausible deniability layer."""
        return self.plausible_deniability.reveal_hidden_layer(combined_data, key, fake_data_length)

    def encrypt_hybrid(self, data: bytes, recipient_pqc_public_key: bytes, pqc_algorithm: str, symmetric_key_length: int = 32) -> Tuple[str, bytes, bytes, bytes, bytes]:
        """Encrypts data using a hybrid approach: PQC KEM for key exchange, symmetric for data."""
        if self.pqc_unit is None:
            raise NotImplementedError("Post-quantum cryptography unit is not available. Use standard symmetric/asymmetric encryption instead.")
        
        # 1. Generate ephemeral PQC key pair and encapsulate a shared secret
        encapsulated_key, shared_secret = self.pqc_unit.encapsulate_kem(pqc_algorithm, recipient_pqc_public_key)

        # 2. Use the shared secret to derive a symmetric key
        # For simplicity, we'll use the shared_secret directly as the symmetric key.
        # In a real scenario, you'd derive a strong symmetric key from the shared_secret using a KDF.
        symmetric_key = shared_secret[:symmetric_key_length] # Truncate or use KDF

        # 3. Encrypt the actual data with the symmetric key
        algo_name, iv, ciphertext, tag = self.encrypt(data, symmetric_key, encryption_type="AES-GCM") # Always use AES-GCM for hybrid

        return pqc_algorithm, encapsulated_key, algo_name, iv, ciphertext, tag

    def decrypt_hybrid(self, pqc_algorithm: str, encapsulated_key: bytes, symmetric_algo_name: str, iv: bytes, ciphertext: bytes, tag: bytes, pqc_private_key: bytes) -> bytes:
        """Decrypts data encrypted with the hybrid approach."""
        if self.pqc_unit is None:
            raise NotImplementedError("Post-quantum cryptography unit is not available. Use standard symmetric/asymmetric encryption instead.")
        
        # 1. Decapsulate the shared secret using the recipient's PQC private key
        shared_secret = self.pqc_unit.decapsulate_kem(pqc_algorithm, pqc_private_key, encapsulated_key)

        # 2. Derive the symmetric key (must match the encryption side)
        symmetric_key = shared_secret[:len(iv)] # Assuming symmetric key length is same as IV for simplicity, or use KDF

        # 3. Decrypt the actual data with the symmetric key
        plaintext = self.decrypt(symmetric_algo_name, symmetric_key, iv, ciphertext, tag)

        return plaintext

    # Placeholder for adding custom algorithms
    def add_custom_symmetric_algorithm(self, name: str, encrypt_func, decrypt_func):
        self.algo_manager.symmetric_algorithms[name] = encrypt_func
        # Need to store decrypt_func as well, perhaps in a separate dict or modify algo_manager
        print(f"Custom symmetric algorithm {name} added.")

    def add_custom_asymmetric_algorithm(self, name: str, encrypt_func, decrypt_func, generate_key_pair_func):
        self.algo_manager.asymmetric_algorithms[name] = encrypt_func
        print(f"Custom asymmetric algorithm {name} added.")


