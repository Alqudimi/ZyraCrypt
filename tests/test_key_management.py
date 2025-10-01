
import unittest
import os
from encryption_system.src.key_management.key_manager import KeyManager

class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        self.key_store_path = "./test_key_store.json"
        self.key_manager = KeyManager(self.key_store_path)

    def tearDown(self):
        if os.path.exists(self.key_store_path):
            os.remove(self.key_store_path)

    def test_generate_and_store_symmetric_key(self):
        key_id = "test_sym_key"
        key = self.key_manager.generate_and_store_symmetric_key(key_id, 256)
        retrieved_key = self.key_manager.get_symmetric_key(key_id)
        self.assertEqual(key, retrieved_key)

    def test_derive_key_pbkdf2(self):
        password = "mysecretpassword"
        salt = os.urandom(16)
        derived_key = self.key_manager.derive_key_from_password(password, salt, "PBKDF2")
        self.assertEqual(len(derived_key), 32) # Default length

    def test_derive_key_argon2(self):
        password = "mysecretpassword"
        salt = os.urandom(16)
        derived_key = self.key_manager.derive_key_from_password(password, salt, "Argon2")
        self.assertEqual(len(derived_key), 32) # Default length

    def test_derive_key_scrypt(self):
        password = "mysecretpassword"
        salt = os.urandom(16)
        derived_key = self.key_manager.derive_key_from_password(password, salt, "scrypt")
        self.assertEqual(len(derived_key), 32) # Default length

    def test_ecdh_key_exchange(self):
        private_key1, public_key1 = self.key_manager.generate_ecdh_key_pair()
        private_key2, public_key2 = self.key_manager.generate_ecdh_key_pair()

        shared_secret1 = self.key_manager.derive_shared_secret_ecdh(private_key1, public_key2)
        shared_secret2 = self.key_manager.derive_shared_secret_ecdh(private_key2, public_key1)
        self.assertEqual(shared_secret1, shared_secret2)

    def test_dh_key_exchange(self):
        parameters = self.key_manager.generate_dh_parameters()
        private_key1, public_key1 = self.key_manager.generate_dh_key_pair(parameters)
        private_key2, public_key2 = self.key_manager.generate_dh_key_pair(parameters)

        shared_secret1 = self.key_manager.derive_shared_secret_dh(private_key1, public_key2)
        shared_secret2 = self.key_manager.derive_shared_secret_dh(private_key2, public_key1)
        self.assertEqual(shared_secret1, shared_secret2)

    # @unittest.skip("Temporarily skipping PQC key pair generation test due to liboqs-python build issues.")
    # def test_pqc_key_pair_generation(self):
    #     public_key, private_key = self.key_manager.generate_pqc_key_pair("Kyber768")
    #     self.assertIsNotNone(public_key)
    #     self.assertIsNotNone(private_key)

    # @unittest.skip("Temporarily skipping QKD simulation test due to liboqs-python build issues.")
    # def test_simulate_qkd(self):
    #     qkd_key = self.key_manager.simulate_qkd(64)
    #     self.assertEqual(len(qkd_key), 64)

if __name__ == '__main__':
    unittest.main()


