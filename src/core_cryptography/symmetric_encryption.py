

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class SymmetricEncryption:
    def __init__(self):
        pass

    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes, bytes]:
        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key must be 128, 192, or 256 bits long (16, 24, or 32 bytes).")

        iv = os.urandom(12)  # GCM recommended IV size is 12 bytes
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return iv, ciphertext, tag

    def decrypt_aes_gcm(self, key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes | None = None) -> bytes:
        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key must be 128, 192, or 256 bits long (16, 24, or 32 bytes).")

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def encrypt_chacha20_poly1305(self, key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
        """Encrypt using ChaCha20-Poly1305 (authenticated encryption)."""
        if len(key) != 32:
            raise ValueError("ChaCha20-Poly1305 key must be 256 bits long (32 bytes).")

        nonce = os.urandom(12)  # ChaCha20-Poly1305 uses 12-byte nonce
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt_chacha20_poly1305(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
        """Decrypt using ChaCha20-Poly1305 (authenticated decryption)."""
        if len(key) != 32:
            raise ValueError("ChaCha20-Poly1305 key must be 256 bits long (32 bytes).")
        if len(nonce) != 12:
            raise ValueError("ChaCha20-Poly1305 nonce must be 96 bits long (12 bytes).")

        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
        return plaintext



