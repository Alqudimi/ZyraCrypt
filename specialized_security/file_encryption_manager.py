
import os
from typing import Optional

class FileEncryptionManager:
    def __init__(self, encryption_framework):
        self.encryption_framework = encryption_framework

    def encrypt_file(self, input_filepath: str, output_filepath: str, key: bytes, associated_data: Optional[bytes] = None):
        """Encrypts a file, preserving metadata (simplified)."""
        with open(input_filepath, "rb") as f_in:
            plaintext = f_in.read()

        # In a real scenario, metadata would be handled separately and securely.
        # For now, we\"ll just encrypt the file content.
        algo_name, iv, ciphertext, tag = self.encryption_framework.encrypt(plaintext, key, associated_data=associated_data)

        # Store algo_name, iv, tag, and ciphertext in the output file.
        # A more robust solution would use a structured format (e.g., JSON header).
        with open(output_filepath, "wb") as f_out:
            f_out.write(algo_name.encode("utf-8") + b"\n")
            f_out.write(iv + b"\n")
            f_out.write(tag + b"\n")
            f_out.write(ciphertext)

    def decrypt_file(self, input_filepath: str, output_filepath: str, key: bytes, associated_data: Optional[bytes] = None):
        """Decrypts a file, restoring original content."""
        with open(input_filepath, "rb") as f_in:
            # Read lines and remove trailing newlines, but keep the original byte length
            algo_name_line = f_in.readline()
            iv_line = f_in.readline()
            tag_line = f_in.readline()
            ciphertext = f_in.read()

            algo_name = algo_name_line.strip().decode("utf-8")
            iv = iv_line.strip(b"\n")
            tag = tag_line.strip(b"\n")

        plaintext = self.encryption_framework.decrypt(algo_name, key, iv, ciphertext, tag, associated_data)

        with open(output_filepath, "wb") as f_out:
            f_out.write(plaintext)


