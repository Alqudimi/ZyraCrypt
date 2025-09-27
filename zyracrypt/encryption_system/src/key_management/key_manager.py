
from .key_generator import KeyGenerator
from .secure_key_store import SecureKeyStore
from .key_exchange import KeyExchange
try:
    from post_quantum_cryptography.post_quantum_cryptography_unit import PostQuantumCryptographyUnit
    PQC_AVAILABLE = True
except ImportError:
    PostQuantumCryptographyUnit = None
    PQC_AVAILABLE = False
from typing import Literal, Union

class KeyManager:
    def __init__(self, key_store_path: str = "./key_store.json"):
        self.key_generator = KeyGenerator()
        self.key_store = SecureKeyStore(key_store_path)
        self.key_exchange = KeyExchange()
        self.pqc_unit = PostQuantumCryptographyUnit() if PQC_AVAILABLE else None

    def generate_and_store_symmetric_key(self, key_id: str, bit_strength: int, expiration_days: int = None) -> bytes:
        """Generates a symmetric key and stores it."""
        key = self.key_generator.generate_symmetric_key(bit_strength)
        self.key_store.store_key(key_id, key, expiration_days)
        return key

    def get_symmetric_key(self, key_id: str) -> bytes:
        """Retrieves a symmetric key from the store."""
        return self.key_store.get_key(key_id)

    def delete_key(self, key_id: str):
        """Deletes a key from the store."""
        self.key_store.delete_key(key_id)

    def derive_key_from_password(self, password: str, salt: bytes, kdf_type: Literal["PBKDF2", "Argon2", "scrypt"], length: int = 32, **kwargs) -> bytes:
        """Derives a key from a password using specified KDF."""
        password_bytes = password.encode("utf-8")
        if kdf_type == "PBKDF2":
            return self.key_generator.derive_key_pbkdf2(password_bytes, salt, length=length, **kwargs)
        elif kdf_type == "Argon2":
            return self.key_generator.derive_key_argon2(password_bytes, salt, length=length, **kwargs)
        elif kdf_type == "scrypt":
            return self.key_generator.derive_key_scrypt(password_bytes, salt, length=length, **kwargs)
        else:
            raise ValueError("Unsupported KDF type.")

    def generate_ecdh_key_pair(self):
        """Generates an ECDH key pair."""
        return self.key_exchange.generate_ecdh_key_pair()

    def derive_shared_secret_ecdh(self, private_key, peer_public_key, length: int = 32) -> bytes:
        """Derives a shared secret using ECDH."""
        return self.key_exchange.derive_shared_secret_ecdh(private_key, peer_public_key, length)

    def generate_dh_parameters(self, prime_length: int = 2048):
        """Generates Diffie-Hellman parameters."""
        return self.key_exchange.generate_dh_parameters(prime_length)

    def generate_dh_key_pair(self, parameters):
        """Generates a Diffie-Hellman key pair from parameters."""
        return self.key_exchange.generate_dh_key_pair(parameters)

    def derive_shared_secret_dh(self, private_key, peer_public_key, length: int = 32) -> bytes:
        """Derives a shared secret using Diffie-Hellman."""
        return self.key_exchange.derive_shared_secret_dh(private_key, peer_public_key, length)

    def generate_pqc_key_pair(self, algorithm_name: str) -> tuple[bytes, bytes]:
        """Generates a PQC KEM key pair."""
        return self.pqc_unit.generate_kem_key_pair(algorithm_name)

    def simulate_qkd(self, length: int = 32) -> bytes:
        """Simulates Quantum Key Distribution (QKD) by generating a random key."""
        return self.pqc_unit.simulate_qkd(length)


