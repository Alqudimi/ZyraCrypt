
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
from encryption_system.src.key_management.key_manager import KeyManager
import os

class SecureMessagingProtocol:
    def __init__(self, key_manager: KeyManager, encryption_framework: EncryptionFramework):
        self.key_manager = key_manager
        self.encryption_framework = encryption_framework

    def send_message(self, sender_private_key_ecdh, recipient_public_key_ecdh, message: bytes) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
        """Sends a secure message with Perfect Forward Secrecy using ephemeral ECDH and AES-GCM."""
        # 1. Generate ephemeral ECDH key pair for the sender
        ephemeral_private_key, ephemeral_public_key = self.key_manager.generate_ecdh_key_pair()

        # 2. Derive a shared secret using the ephemeral private key and recipient's public key
        shared_secret = self.key_manager.derive_shared_secret_ecdh(ephemeral_private_key, recipient_public_key_ecdh)

        # 3. Use the shared secret as the symmetric key for AES-GCM encryption
        # In a real protocol, a KDF would be used to derive a strong key from the shared secret.
        symmetric_key = shared_secret[:32] # Use first 32 bytes for AES-256

        # 4. Encrypt the message with AES-GCM
        iv, ciphertext, tag = self.encryption_framework.symmetric_enc.encrypt_aes_gcm(symmetric_key, message)

        # Return ephemeral public key, IV, ciphertext, and tag
        # The recipient will use their private key and the sender's ephemeral public key to derive the same shared secret.
        return ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ), iv, ciphertext, tag

    def receive_message(self, recipient_private_key_ecdh, sender_ephemeral_public_key_pem: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """Receives and decrypts a secure message."""
        # 1. Load the sender's ephemeral public key
        sender_ephemeral_public_key = serialization.load_pem_public_key(
            sender_ephemeral_public_key_pem
        )

        # 2. Derive the shared secret using recipient's private key and sender's ephemeral public key
        shared_secret = self.key_manager.derive_shared_secret_ecdh(recipient_private_key_ecdh, sender_ephemeral_public_key)

        # 3. Use the shared secret as the symmetric key for AES-GCM decryption
        symmetric_key = shared_secret[:32] # Use first 32 bytes for AES-256

        # 4. Decrypt the message
        plaintext = self.encryption_framework.symmetric_enc.decrypt_aes_gcm(symmetric_key, iv, ciphertext, tag)
        return plaintext


