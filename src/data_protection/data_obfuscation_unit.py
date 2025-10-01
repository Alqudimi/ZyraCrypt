

class DataObfuscationUnit:
    def __init__(self):
        pass

    def obfuscate_data(self, data: bytes, key: bytes = b"default_obfuscation_key") -> bytes:
        """Applies a simple XOR obfuscation to data. Not for cryptographic security, but for basic obfuscation."""
        if not key:
            raise ValueError("XOR key cannot be empty.")
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

    def deobfuscate_data(self, obfuscated_data: bytes, key: bytes = b"default_obfuscation_key") -> bytes:
        """Reverses the XOR obfuscation."""
        return self.obfuscate_data(obfuscated_data, key) # XOR is symmetric


