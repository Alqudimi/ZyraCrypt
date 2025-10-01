
import unittest
import os
from encryption_system.src.specialized_security.file_encryption_manager import FileEncryptionManager
from encryption_system.src.specialized_security.secure_deletion_unit import SecureDeletionUnit
from encryption_system.src.specialized_security.steganography_unit import SteganographyUnit
from encryption_system.src.specialized_security.secure_session_manager import SecureSessionManager
from encryption_system.src.key_management.key_manager import KeyManager
from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework

class TestSpecializedSecurity(unittest.TestCase):
    def setUp(self):
        self.encryption_framework = EncryptionFramework()
        self.file_encryption_manager = FileEncryptionManager(self.encryption_framework)
        self.secure_deletion_unit = SecureDeletionUnit()
        self.steganography_unit = SteganographyUnit()
        self.secure_session_manager = SecureSessionManager()
        self.key_manager = KeyManager()
        self.test_file_path = "./test_file.txt"
        self.encrypted_file_path = "./test_file.enc"
        self.stego_image_path = "./test_image.png"
        self.output_image_path = "./output_image.png"
        self.test_data = b"This is a secret message for file encryption and steganography."

        # Create a dummy image for steganography tests
        from PIL import Image
        img = Image.new("RGB", (100, 100), color = "red")
        img.save(self.stego_image_path)

    def tearDown(self):
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        if os.path.exists(self.encrypted_file_path):
            os.remove(self.encrypted_file_path)
        if os.path.exists(self.stego_image_path):
            os.remove(self.stego_image_path)
        if os.path.exists(self.output_image_path):
            os.remove(self.output_image_path)

    def test_file_encryption_decryption(self):
        key = os.urandom(32)
        with open(self.test_file_path, "wb") as f:
            f.write(self.test_data)
        
        self.file_encryption_manager.encrypt_file(self.test_file_path, self.encrypted_file_path, key)
        self.assertTrue(os.path.exists(self.encrypted_file_path))

        # Decrypt to a temporary file for verification
        temp_decrypted_file_path = "./temp_decrypted_file.txt"
        self.file_encryption_manager.decrypt_file(self.encrypted_file_path, temp_decrypted_file_path, key)
        with open(temp_decrypted_file_path, "rb") as f_decrypted:
            decrypted_data = f_decrypted.read()
        self.assertEqual(self.test_data, decrypted_data)
        os.remove(temp_decrypted_file_path)

    def test_secure_deletion(self):
        with open(self.test_file_path, "wb") as f:
            f.write(b"sensitive data to be deleted")
        self.assertTrue(os.path.exists(self.test_file_path))
        self.secure_deletion_unit.dod_5220_22_m_erase(self.test_file_path)
        self.assertFalse(os.path.exists(self.test_file_path))

    def test_steganography_hide_reveal(self):
        self.steganography_unit.embed_data(self.stego_image_path, self.test_data, self.output_image_path)
        self.assertTrue(os.path.exists(self.output_image_path))
        revealed_data = self.steganography_unit.extract_data(self.output_image_path)
        self.assertEqual(self.test_data, revealed_data)

    def test_secure_session_management(self):
        session_id = self.secure_session_manager.create_session()
        self.assertIsNotNone(session_id)
        
        session_data = {"user": "test_user", "role": "admin"}
        self.secure_session_manager.set_session_data(session_id, session_data)
        retrieved_data = self.secure_session_manager.get_session_data(session_id)
        
        # Remove 'created_at' key for comparison as it's dynamically generated
        if 'created_at' in retrieved_data:
            del retrieved_data['created_at']

        self.assertEqual(session_data, retrieved_data)

        self.secure_session_manager.destroy_session(session_id)
        with self.assertRaises(KeyError):
            self.secure_session_manager.get_session_data(session_id)

if __name__ == '__main__':
    unittest.main()


