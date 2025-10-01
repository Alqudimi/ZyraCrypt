
import unittest
import os
from encryption_system.src.data_protection.data_type_manager import DataTypeManager
from encryption_system.src.data_protection.compression_unit import CompressionUnit
from encryption_system.src.data_protection.data_obfuscation_unit import DataObfuscationUnit
from encryption_system.src.data_protection.secure_memory_handling import SecureMemoryHandling

class TestDataProtection(unittest.TestCase):
    def setUp(self):
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

if __name__ == '__main__':
    unittest.main()


