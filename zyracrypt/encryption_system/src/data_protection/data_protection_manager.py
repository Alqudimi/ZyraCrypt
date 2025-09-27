
from typing import Union
from .data_type_manager import DataTypeManager
from .compression_unit import CompressionUnit
from .data_obfuscation_unit import DataObfuscationUnit
from .secure_memory_handling import SecureMemoryHandling

class DataProtectionManager:
    def __init__(self):
        self.data_type_manager = DataTypeManager()
        self.compression_unit = CompressionUnit()
        self.data_obfuscation_unit = DataObfuscationUnit()
        self.secure_memory_handling = SecureMemoryHandling()

    def prepare_data_for_encryption(self, data: Union[str, bytes, dict], obfuscation_key: bytes | None = None) -> tuple[bytes, str]:
        """Serializes, compresses, and optionally obfuscates data before encryption."""
        original_type = self.data_type_manager.get_type_name(data)
        serialized_data = self.data_type_manager.serialize(data)
        compressed_data = self.compression_unit.compress_data(serialized_data)
        
        if obfuscation_key:
            obfuscated_data = self.data_obfuscation_unit.obfuscate_data(compressed_data, obfuscation_key)
            return obfuscated_data, original_type
        else:
            return compressed_data, original_type

    def restore_data_after_decryption(self, processed_data: bytes, original_type: str, obfuscation_key: bytes | None = None) -> Union[str, bytes, dict]:
        """De-obfuscates, decompresses, and deserializes data after decryption."""
        if obfuscation_key:
            deobfuscated_data = self.data_obfuscation_unit.deobfuscate_data(processed_data, obfuscation_key)
            decompressed_data = self.compression_unit.decompress_data(deobfuscated_data)
        else:
            decompressed_data = self.compression_unit.decompress_data(processed_data)

        restored_data = self.data_type_manager.deserialize(decompressed_data, original_type)
        return restored_data

    def zeroize_sensitive_data(self, data: bytearray):
        """Zeroizes sensitive data in memory."""
        self.secure_memory_handling.zeroize_data(data)

    def make_data_secure(self, data: bytes) -> bytearray:
        """Creates a secure bytearray that can be zeroized."""
        return bytearray(data)

    def unsecure_data(self, data: bytearray) -> bytes:
        """Converts secure bytearray back to regular bytes."""
        return bytes(data)


