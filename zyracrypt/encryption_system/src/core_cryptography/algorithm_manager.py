
from typing import Literal, Union
from .symmetric_encryption import SymmetricEncryption
from .asymmetric_encryption import AsymmetricEncryption

class AlgorithmManager:
    def __init__(self):
        self.symmetric_algorithms = {
            "AES-GCM": SymmetricEncryption().encrypt_aes_gcm,
            "ChaCha20-Poly1305": SymmetricEncryption().encrypt_chacha20_poly1305,
        }
        self.asymmetric_algorithms = {
            "RSA": AsymmetricEncryption().encrypt_rsa_oaep,
            "ECC": AsymmetricEncryption().sign_ecc,  # Use consistent signing function for ECC
        }

    def select_symmetric_algorithm(self, data_size: int, security_level: Literal["high", "medium", "low"] = "high") -> str:
        """Selects a symmetric algorithm based on data size and security level."""
        if security_level == "high" or data_size > 1024 * 1024: # For large data or high security, prefer AES-GCM
            return "AES-GCM"
        else:
            return "ChaCha20-Poly1305"

    def select_asymmetric_algorithm(self, security_level: Literal["high", "medium", "low"] = "high") -> str:
        """Selects an asymmetric algorithm based on security level."""
        if security_level == "high":
            return "ECC"
        else:
            return "RSA"

    def get_symmetric_encryptor(self, algorithm_name: str):
        return self.symmetric_algorithms.get(algorithm_name)

    def get_asymmetric_encryptor(self, algorithm_name: str):
        return self.asymmetric_algorithms.get(algorithm_name)


