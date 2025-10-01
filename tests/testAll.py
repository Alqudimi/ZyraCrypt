import unittest
import os
import sys

# إضافة المسار للوحدات المطلوبة
sys.path.append('./encryption_system/src')

class TestCompleteEncryptionSystem(unittest.TestCase):
    """اختبار شامل لنظام التشفير بالكامل"""
    
    def setUp(self):
        """تهيئة البيئة للاختبارات"""
        self.test_files = []
        
    def tearDown(self):
        """تنظيف الملفات المؤقتة بعد كل اختبار"""
        for file_path in self.test_files:
            if os.path.exists(file_path):
                os.remove(file_path)

class TestCoreCryptography(TestCompleteEncryptionSystem):
    """اختبارات التشفير الأساسي"""
    
    def setUp(self):
        super().setUp()
        from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
        from encryption_system.src.key_management.key_manager import KeyManager
        
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

class TestKeyManagement(TestCompleteEncryptionSystem):
    """اختبارات إدارة المفاتيح"""
    
    def setUp(self):
        super().setUp()
        from encryption_system.src.key_management.key_manager import KeyManager
        
        self.key_store_path = "./test_key_store.json"
        self.key_manager = KeyManager(self.key_store_path)
        self.test_files.append(self.key_store_path)

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

class TestDataProtection(TestCompleteEncryptionSystem):
    """اختبارات حماية البيانات"""
    
    def setUp(self):
        super().setUp()
        from encryption_system.src.data_protection.data_type_manager import DataTypeManager
        from encryption_system.src.data_protection.compression_unit import CompressionUnit
        from encryption_system.src.data_protection.data_obfuscation_unit import DataObfuscationUnit
        from encryption_system.src.data_protection.secure_memory_handling import SecureMemoryHandling
        
        self.data_type_manager = DataTypeManager()
        self.compression_unit = CompressionUnit()
        self.data_obfuscation_unit = DataObfuscationUnit()
        self.secure_memory_handling = SecureMemoryHandling()
        self.test_data_str = "This is some test data for data protection modules."
        self.test_data_bytes = self.test_data_str.encode("utf-8")

    def test_detect_data_type(self):
        self.assertEqual(self.data_type_manager.detect_data_type(b"<root><item>value</item></root>"), "XML")
        self.assertEqual(self.data_type_manager.detect_data_type(b"{\"key\": \"value\"}"), "JSON")
        self.assertEqual(self.data_type_manager.detect_data_type(b"plain text"), "TEXT")
        self.assertEqual(self.data_type_manager.detect_data_type(b"\x89PNG\r\n\x1a\n"), "BINARY")

    def test_compress_decompress(self):
        compressed_data = self.compression_unit.compress_data(self.test_data_bytes)
        decompressed_data = self.compression_unit.decompress_data(compressed_data)
        self.assertEqual(self.test_data_bytes, decompressed_data)

    def test_obfuscate_deobfuscate(self):
        obfuscated_data = self.data_obfuscation_unit.obfuscate_data(self.test_data_bytes)
        deobfuscated_data = self.data_obfuscation_unit.deobfuscate_data(obfuscated_data)
        self.assertEqual(self.test_data_bytes, deobfuscated_data)

    def test_zeroize_memory(self):
        sensitive_data = bytearray(b"secret_info")
        self.secure_memory_handling.zeroize_data(sensitive_data)
        self.assertEqual(sensitive_data, bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))

class TestSpecializedSecurity(TestCompleteEncryptionSystem):
    """اختبارات الأمن المتخصص"""
    
    def setUp(self):
        super().setUp()
        from encryption_system.src.specialized_security.file_encryption_manager import FileEncryptionManager
        from encryption_system.src.specialized_security.secure_deletion_unit import SecureDeletionUnit
        from encryption_system.src.specialized_security.steganography_unit import SteganographyUnit
        from encryption_system.src.specialized_security.secure_session_manager import SecureSessionManager
        from encryption_system.src.key_management.key_manager import KeyManager
        from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
        
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

        # إضافة الملفات إلى قائمة التنظيف
        self.test_files.extend([
            self.test_file_path, 
            self.encrypted_file_path,
            self.stego_image_path,
            self.output_image_path
        ])

        # إنشاء صورة وهمية لاختبارات الإخفاء
        try:
            from PIL import Image
            img = Image.new("RGB", (100, 100), color = "red")
            img.save(self.stego_image_path)
        except ImportError:
            self.skipTest("PIL not available, skipping steganography tests")

    def test_file_encryption_decryption(self):
        key = os.urandom(32)
        with open(self.test_file_path, "wb") as f:
            f.write(self.test_data)
        
        self.file_encryption_manager.encrypt_file(self.test_file_path, self.encrypted_file_path, key)
        self.assertTrue(os.path.exists(self.encrypted_file_path))

        # فك التشفير إلى ملف مؤقت للتحقق
        temp_decrypted_file_path = "./temp_decrypted_file.txt"
        self.test_files.append(temp_decrypted_file_path)
        
        self.file_encryption_manager.decrypt_file(self.encrypted_file_path, temp_decrypted_file_path, key)
        with open(temp_decrypted_file_path, "rb") as f_decrypted:
            decrypted_data = f_decrypted.read()
        self.assertEqual(self.test_data, decrypted_data)

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
        
        # إزالة المفتاح 'created_at' للمقارنة لأنه يتم إنشاؤه ديناميكيًا
        if 'created_at' in retrieved_data:
            del retrieved_data['created_at']

        self.assertEqual(session_data, retrieved_data)

        self.secure_session_manager.destroy_session(session_id)
        with self.assertRaises(KeyError):
            self.secure_session_manager.get_session_data(session_id)

class TestAdvancedFeatures(TestCompleteEncryptionSystem):
    """اختبارات الميزات المتقدمة"""
    
    def setUp(self):
        super().setUp()
        from encryption_system.src.advanced_features.secure_messaging_protocol import SecureMessagingProtocol
        from encryption_system.src.advanced_features.cryptographic_audit_log import CryptographicAuditLog
        from encryption_system.src.advanced_features.tamper_resistant_data_structures import TamperResistantDataStructures
        from encryption_system.src.key_management.key_manager import KeyManager
        from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework
        
        self.key_manager = KeyManager()
        self.encryption_framework = EncryptionFramework()
        self.secure_messaging_protocol = SecureMessagingProtocol(self.key_manager, self.encryption_framework)
        
        self.audit_log_path = "./test_audit.log"
        self.cryptographic_audit_log = CryptographicAuditLog(self.audit_log_path)
        self.tamper_resistant_data_structures = TamperResistantDataStructures()
        
        self.test_files.append(self.audit_log_path)

        # إنشاء أزواج مفاتيح ECDH لاختبارات بروتوكول المراسلة
        self.sender_private_key, self.sender_public_key = self.key_manager.generate_ecdh_key_pair()
        self.recipient_private_key, self.recipient_public_key = self.key_manager.generate_ecdh_key_pair()

    def test_secure_messaging_protocol(self):
        message = b"Hello, secure world!"
        ephemeral_public_key_pem, iv, ciphertext, tag = self.secure_messaging_protocol.send_message(
            self.sender_private_key, self.recipient_public_key, message
        )
        
        decrypted_message = self.secure_messaging_protocol.receive_message(
            self.recipient_private_key, ephemeral_public_key_pem, iv, ciphertext, tag
        )
        self.assertEqual(message, decrypted_message)

    def test_cryptographic_audit_log(self):
        self.cryptographic_audit_log.log_event("ENCRYPTION_SUCCESS", "user123", {"file": "doc1.txt"})
        logs = self.cryptographic_audit_log.get_logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["event_type"], "ENCRYPTION_SUCCESS")
        self.assertEqual(logs[0]["user_id"], "user123")
        self.assertEqual(logs[0]["details"]["file"], "doc1.txt")

    def test_hash_chain(self):
        data_blocks = [b"block1", b"block2", b"block3"]
        hash_chain = self.tamper_resistant_data_structures.create_hash_chain(data_blocks)
        self.assertTrue(self.tamper_resistant_data_structures.verify_hash_chain(data_blocks, hash_chain))

        # اختبار مع بيانات معدلة
        tampered_data_blocks = [b"block1", b"block_tampered", b"block3"]
        self.assertFalse(self.tamper_resistant_data_structures.verify_hash_chain(tampered_data_blocks, hash_chain))

    def test_merkle_tree(self):
        data_blocks = [b"txA", b"txB", b"txC", b"txD"]
        merkle_root = self.tamper_resistant_data_structures.get_merkle_root(data_blocks)
        self.assertIsNotNone(merkle_root)

        # التحقق المبسط لإثبات Merkle (يتطلب إنشاء إثبات فعلي ليتم اختباره بالكامل)
        # للتوضيح، سنتحقق فقط مما إذا كان الجذر غير فارغ
        self.assertTrue(len(merkle_root) > 0)

def run_all_tests():
    """تشغيل جميع اختبارات النظام"""
    # إنشاء مجموعة اختبارات
    test_suite = unittest.TestSuite()
    
    # إضافة جميع فئات الاختبار
    test_suite.addTest(unittest.makeSuite(TestCoreCryptography))
    test_suite.addTest(unittest.makeSuite(TestKeyManagement))
    test_suite.addTest(unittest.makeSuite(TestDataProtection))
    test_suite.addTest(unittest.makeSuite(TestSpecializedSecurity))
    test_suite.addTest(unittest.makeSuite(TestAdvancedFeatures))
    
    # تشغيل الاختبارات
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result

if __name__ == '__main__':
    print("تشغيل جميع اختبارات نظام التشفير...")
    print("=" * 50)
    
    result = run_all_tests()
    
    print("=" * 50)
    if result.wasSuccessful():
        print("✅ جميع الاختبارات نجحت!")
    else:
        print(f"❌ فشل بعض الاختبارات: {len(result.failures)} فشل، {len(result.errors)} أخطاء")
    
    sys.exit(0 if result.wasSuccessful() else 1)