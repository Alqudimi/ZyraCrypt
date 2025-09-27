
import unittest
import os
from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
from encryption_system.src.key_management.key_manager import KeyManager

class TestCoreCryptography(unittest.TestCase):
    def setUp(self):
        self.encryption_framework = EncryptionFramework()
        self.key_manager = KeyManager()
        self.symmetric_key = os.urandom(32) # AES-256 key
        self.test_data = b"This is a test message for encryption and decryption."

    def test_aes_gcm_encryption_decryption(self):
        iv, ciphertext, tag = self.encryption_framework.symmetric_enc.encrypt_aes_gcm(self.symmetric_key, self.test_data)
        decrypted_data = self.encryption_framework.symmetric_enc.decrypt_aes_gcm(self.symmetric_key, iv, ciphertext, tag)
        self.assertEqual(self.test_data, decrypted_data)

    def test_chacha20_encryption_decryption(self):
        nonce = os.urandom(16)
        ciphertext = self.encryption_framework.symmetric_enc.encrypt_chacha20(self.symmetric_key, nonce, self.test_data)
        decrypted_data = self.encryption_framework.symmetric_enc.decrypt_chacha20(self.symmetric_key, nonce, ciphertext)
        self.assertEqual(self.test_data, decrypted_data)

    def test_rsa_encryption_decryption(self):
        private_key, public_key = self.encryption_framework.asymmetric_enc.generate_rsa_key_pair()
        # RSA encryption has size limitations, so we'll encrypt a smaller key
        small_data = os.urandom(32) # Encrypt a symmetric key with RSA
        encrypted_small_data = self.encryption_framework.asymmetric_enc.encrypt_rsa_oaep(public_key, small_data)
        decrypted_small_data = self.encryption_framework.asymmetric_enc.decrypt_rsa_oaep(private_key, encrypted_small_data)
        self.assertEqual(small_data, decrypted_small_data)

    def test_ecc_signing_verification(self):
        private_key, public_key = self.encryption_framework.asymmetric_enc.generate_ecc_key_pair()
        signature = self.encryption_framework.asymmetric_enc.sign_ecc(private_key, self.test_data)
        self.assertTrue(self.encryption_framework.asymmetric_enc.verify_ecc(public_key, self.test_data, signature))

    def test_ecc_signing_verification_tampered(self):
        private_key, public_key = self.encryption_framework.asymmetric_enc.generate_ecc_key_pair()
        signature = self.encryption_framework.asymmetric_enc.sign_ecc(private_key, self.test_data)
        tampered_data = self.test_data + b"tamper"
        self.assertFalse(self.encryption_framework.asymmetric_enc.verify_ecc(public_key, tampered_data, signature))

    def test_plausible_deniability(self):
        real_data = b"This is the secret real data."
        fake_data = b"This is the plausible fake data that will be shown."
        pd_key = os.urandom(32)

        combined_data = self.encryption_framework.create_plausible_deniability_layer(real_data, fake_data, pd_key)
        revealed_data = self.encryption_framework.reveal_plausible_deniability_layer(combined_data, pd_key, len(fake_data))
        self.assertEqual(real_data, revealed_data)

    # @unittest.skip("Temporarily skipping PQC hybrid encryption test due to liboqs-python build issues.")
    # def test_hybrid_encryption_decryption(self):
    #     # Generate PQC KEM key pair for recipient
    #     pqc_algo = "Kyber768"
    #     recipient_pqc_public_key, recipient_pqc_private_key = self.key_manager.generate_pqc_key_pair(pqc_algo)

    #     # Encrypt data using hybrid approach
    #     pqc_algo_used, encapsulated_key, symmetric_algo_name, iv, ciphertext, tag = \
    #         self.encryption_framework.encrypt_hybrid(self.test_data, recipient_pqc_public_key, pqc_algo)

    #     # Decrypt data using hybrid approach
    #     decrypted_data = self.encryption_framework.decrypt_hybrid(
    #         pqc_algo_used, encapsulated_key, symmetric_algo_name, iv, ciphertext, tag, recipient_pqc_private_key
    #     )
    #     self.assertEqual(self.test_data, decrypted_data)

if __name__ == '__main__':
    unittest.main()


