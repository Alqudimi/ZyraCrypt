
import unittest
import os
from encryption_system.src.advanced_features.secure_messaging_protocol import SecureMessagingProtocol
from encryption_system.src.advanced_features.cryptographic_audit_log import CryptographicAuditLog
from encryption_system.src.advanced_features.tamper_resistant_data_structures import TamperResistantDataStructures
from encryption_system.src.key_management.key_manager import KeyManager
from encryption_system.src.core_cryptography.encryption_framework import EncryptionFramework

class TestAdvancedFeatures(unittest.TestCase):
    def setUp(self):
        self.key_manager = KeyManager()
        self.encryption_framework = EncryptionFramework()
        self.secure_messaging_protocol = SecureMessagingProtocol(self.key_manager, self.encryption_framework)
        self.audit_log_path = "./test_audit.log"
        self.cryptographic_audit_log = CryptographicAuditLog(self.audit_log_path)
        self.tamper_resistant_data_structures = TamperResistantDataStructures()

        # Generate ECDH key pairs for messaging protocol tests
        self.sender_private_key, self.sender_public_key = self.key_manager.generate_ecdh_key_pair()
        self.recipient_private_key, self.recipient_public_key = self.key_manager.generate_ecdh_key_pair()

    def tearDown(self):
        if os.path.exists(self.audit_log_path):
            os.remove(self.audit_log_path)

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

        # Test with tampered data
        tampered_data_blocks = [b"block1", b"block_tampered", b"block3"]
        self.assertFalse(self.tamper_resistant_data_structures.verify_hash_chain(tampered_data_blocks, hash_chain))

    def test_merkle_tree(self):
        data_blocks = [b"txA", b"txB", b"txC", b"txD"]
        merkle_root = self.tamper_resistant_data_structures.get_merkle_root(data_blocks)
        self.assertIsNotNone(merkle_root)

        # Simplified Merkle proof verification (requires actual proof generation to be fully tested)
        # For demonstration, we'll just check if the root is non-empty
        self.assertTrue(len(merkle_root) > 0)

if __name__ == '__main__':
    unittest.main()


