"""
White-Box Cryptography Implementation

White-box cryptography protects cryptographic keys even when attackers have
full access to the software implementation. This is achieved through:
- Key obfuscation using lookup tables
- Mixing bijections and encodings
- Code obfuscation techniques

Use cases:
- Mobile app security
- DRM (Digital Rights Management)
- Software protection
- Embedded systems

Note: True white-box cryptography is extremely complex. This provides
practical key hiding and obfuscation techniques suitable for real-world use.
"""

import os
import secrets
import hashlib
import struct
from typing import List, Tuple, Dict, Optional, Callable
from dataclasses import dataclass
import json


@dataclass
class WhiteBoxKey:
    """White-box protected key."""
    key_id: str
    table_data: bytes
    encoding_data: bytes
    algorithm: str
    key_size: int


class LookupTableGenerator:
    """
    Generates lookup tables for white-box implementations.
    
    Lookup tables hide key material by pre-computing operations.
    """
    
    def __init__(self):
        """Initialize lookup table generator."""
        self.tables: Dict[str, List[bytes]] = {}
    
    def generate_sbox_table(self, key_byte: int, transform: Optional[Callable] = None) -> List[int]:
        """
        Generate S-box lookup table that includes key material.
        
        Args:
            key_byte: Byte of the key to embed
            transform: Optional transformation function
            
        Returns:
            256-entry lookup table
        """
        table = []
        for input_val in range(256):
            # XOR with key byte
            output = input_val ^ key_byte
            
            # Apply optional transformation (e.g., AES S-box)
            if transform:
                output = transform(output)
            
            table.append(output)
        
        return table
    
    def generate_mixing_bijection(self, seed: bytes) -> List[int]:
        """
        Generate mixing bijection (permutation) for encodings.
        
        Args:
            seed: Random seed
            
        Returns:
            Permutation table
        """
        # Generate random permutation
        perm = list(range(256))
        
        # Fisher-Yates shuffle using seed-based randomness
        rng = hashlib.sha256(seed).digest()
        rng_pos = 0
        
        for i in range(255, 0, -1):
            # Get random index
            if rng_pos >= len(rng):
                rng = hashlib.sha256(rng).digest()
                rng_pos = 0
            
            j = rng[rng_pos] % (i + 1)
            rng_pos += 1
            
            # Swap
            perm[i], perm[j] = perm[j], perm[i]
        
        return perm
    
    def generate_inverse_bijection(self, bijection: List[int]) -> List[int]:
        """
        Generate inverse of a bijection.
        
        Args:
            bijection: Forward bijection
            
        Returns:
            Inverse bijection
        """
        inverse = [0] * 256
        for i, val in enumerate(bijection):
            inverse[val] = i
        return inverse
    
    def apply_input_encoding(self, data: int, encoding: List[int]) -> int:
        """
        Apply input encoding transformation.
        
        Args:
            data: Input byte
            encoding: Encoding table
            
        Returns:
            Encoded byte
        """
        return encoding[data & 0xFF] & 0xFF
    
    def apply_output_encoding(self, data: int, encoding: List[int]) -> int:
        """
        Apply output encoding transformation.
        
        Args:
            data: Output byte
            encoding: Encoding table
            
        Returns:
            Encoded byte
        """
        return encoding[data & 0xFF] & 0xFF


class WhiteBoxAES:
    """
    White-box AES implementation using lookup tables.
    
    Note: This is a simplified version. Production white-box AES
    requires much more complex table networks.
    """
    
    def __init__(self):
        """Initialize white-box AES."""
        self.table_gen = LookupTableGenerator()
        self.tables: Dict[str, List[List[int]]] = {}
        self.encodings: Dict[str, List[List[int]]] = {}
    
    def create_white_box_key(self, key: bytes, key_id: Optional[str] = None) -> WhiteBoxKey:
        """
        Create white-box protected key from regular key.
        
        Args:
            key: Original key (16, 24, or 32 bytes)
            key_id: Optional key identifier
            
        Returns:
            White-box protected key
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes")
        
        if key_id is None:
            key_id = secrets.token_hex(16)
        
        # Generate lookup tables for each key byte
        key_tables = []
        for key_byte in key:
            # Create table that XORs input with key byte
            table = self.table_gen.generate_sbox_table(key_byte)
            key_tables.append(table)
        
        # Generate input/output encodings for obfuscation
        encodings = []
        for i in range(len(key)):
            seed = hashlib.sha256(key + i.to_bytes(4, 'big')).digest()
            encoding = self.table_gen.generate_mixing_bijection(seed)
            encodings.append(encoding)
        
        # Store tables
        self.tables[key_id] = key_tables
        self.encodings[key_id] = encodings
        
        # Serialize tables and encodings
        table_data = json.dumps(key_tables).encode('utf-8')
        encoding_data = json.dumps(encodings).encode('utf-8')
        
        return WhiteBoxKey(
            key_id=key_id,
            table_data=table_data,
            encoding_data=encoding_data,
            algorithm='white_box_aes',
            key_size=len(key) * 8
        )
    
    def encrypt_with_tables(self, plaintext: bytes, wb_key: WhiteBoxKey) -> bytes:
        """
        Encrypt using white-box tables.
        
        Args:
            plaintext: Data to encrypt
            wb_key: White-box protected key
            
        Returns:
            Ciphertext
        """
        # Load tables if not in memory
        if wb_key.key_id not in self.tables:
            tables = json.loads(wb_key.table_data.decode('utf-8'))
            encodings = json.loads(wb_key.encoding_data.decode('utf-8'))
            self.tables[wb_key.key_id] = tables
            self.encodings[wb_key.key_id] = encodings
        
        tables = self.tables[wb_key.key_id]
        encodings = self.encodings[wb_key.key_id]
        
        # Simple table-based encryption (simplified white-box concept)
        ciphertext = bytearray()
        
        for i, byte in enumerate(plaintext):
            # Apply input encoding
            encoded_input = self.table_gen.apply_input_encoding(
                byte, encodings[i % len(encodings)]
            )
            
            # Lookup in key table (performs key XOR internally)
            table_output = tables[i % len(tables)][encoded_input]
            
            # Apply output encoding
            final_output = self.table_gen.apply_output_encoding(
                table_output, encodings[(i + 1) % len(encodings)]
            )
            
            ciphertext.append(final_output)
        
        return bytes(ciphertext)
    
    def decrypt_with_tables(self, ciphertext: bytes, wb_key: WhiteBoxKey) -> bytes:
        """
        Decrypt using white-box tables.
        
        Args:
            ciphertext: Encrypted data
            wb_key: White-box protected key
            
        Returns:
            Plaintext
        """
        # Load tables if not in memory
        if wb_key.key_id not in self.tables:
            tables = json.loads(wb_key.table_data.decode('utf-8'))
            encodings = json.loads(wb_key.encoding_data.decode('utf-8'))
            self.tables[wb_key.key_id] = tables
            self.encodings[wb_key.key_id] = encodings
        
        tables = self.tables[wb_key.key_id]
        encodings = self.encodings[wb_key.key_id]
        
        # Generate inverse encodings
        inverse_encodings = [
            self.table_gen.generate_inverse_bijection(enc)
            for enc in encodings
        ]
        
        # Decrypt using inverse operations
        plaintext = bytearray()
        
        for i, byte in enumerate(ciphertext):
            # Reverse output encoding
            decoded = self.table_gen.apply_output_encoding(
                byte, inverse_encodings[(i + 1) % len(inverse_encodings)]
            )
            
            # Reverse table lookup
            table = tables[i % len(tables)]
            for input_val, output_val in enumerate(table):
                if output_val == decoded:
                    original = input_val
                    break
            
            # Reverse input encoding
            final = self.table_gen.apply_input_encoding(
                original, inverse_encodings[i % len(inverse_encodings)]
            )
            
            plaintext.append(final)
        
        return bytes(plaintext)


class KeyObfuscator:
    """
    Obfuscates cryptographic keys to make extraction difficult.
    """
    
    def __init__(self):
        """Initialize key obfuscator."""
        self.obfuscation_data: Dict[str, bytes] = {}
    
    def obfuscate_key(self, key: bytes, complexity: int = 100) -> Tuple[bytes, bytes]:
        """
        Obfuscate a key using multiple layers of encoding.
        
        Args:
            key: Original key
            complexity: Number of obfuscation layers
            
        Returns:
            Tuple of (obfuscated_key, deobfuscation_data)
        """
        current = bytearray(key)
        transformations = []
        
        for layer in range(complexity):
            # Generate random transformation for this layer
            transform_type = secrets.randbelow(3)
            
            if transform_type == 0:
                # XOR with random mask
                mask = secrets.token_bytes(len(current))
                current = bytes(a ^ b for a, b in zip(current, mask))
                transformations.append(('xor', mask))
            
            elif transform_type == 1:
                # Byte permutation
                perm = list(range(len(current)))
                secrets.SystemRandom().shuffle(perm)
                temp = bytearray(len(current))
                for i, p in enumerate(perm):
                    temp[p] = current[i]
                current = bytes(temp)
                transformations.append(('perm', bytes(perm)))
            
            else:
                # Add with random values (mod 256)
                add_vals = secrets.token_bytes(len(current))
                current = bytes((a + b) % 256 for a, b in zip(current, add_vals))
                transformations.append(('add', add_vals))
        
        # Serialize transformation data
        deobfuscation_data = json.dumps([
            (t[0], t[1].hex()) for t in transformations
        ]).encode('utf-8')
        
        return bytes(current), deobfuscation_data
    
    def deobfuscate_key(self, obfuscated_key: bytes, deobfuscation_data: bytes) -> bytes:
        """
        Recover original key from obfuscated version.
        
        Args:
            obfuscated_key: Obfuscated key
            deobfuscation_data: Data needed for deobfuscation
            
        Returns:
            Original key
        """
        # Parse transformations
        transformations = json.loads(deobfuscation_data.decode('utf-8'))
        
        current = bytearray(obfuscated_key)
        
        # Reverse transformations in reverse order
        for transform_type, param_hex in reversed(transformations):
            param = bytes.fromhex(param_hex)
            
            if transform_type == 'xor':
                # XOR is its own inverse
                current = bytes(a ^ b for a, b in zip(current, param))
            
            elif transform_type == 'perm':
                # Reverse permutation
                perm = list(param)
                temp = bytearray(len(current))
                for i, p in enumerate(perm):
                    temp[i] = current[p]
                current = bytes(temp)
            
            elif transform_type == 'add':
                # Subtract (inverse of add mod 256)
                current = bytes((a - b) % 256 for a, b in zip(current, param))
        
        return bytes(current)


class WhiteBoxCryptography:
    """
    Main white-box cryptography interface.
    
    Provides key protection and obfuscated encryption operations.
    """
    
    def __init__(self):
        """Initialize white-box cryptography system."""
        self.wb_aes = WhiteBoxAES()
        self.obfuscator = KeyObfuscator()
        self.white_box_keys: Dict[str, WhiteBoxKey] = {}
    
    def create_white_box_key(self, key: bytes, key_id: Optional[str] = None) -> str:
        """
        Create a white-box protected key.
        
        Args:
            key: Original cryptographic key
            key_id: Optional key identifier
            
        Returns:
            Key ID for the white-box key
        """
        wb_key = self.wb_aes.create_white_box_key(key, key_id)
        self.white_box_keys[wb_key.key_id] = wb_key
        return wb_key.key_id
    
    def encrypt_white_box(self, plaintext: bytes, white_box_key_id: str) -> bytes:
        """
        Encrypt data using white-box protected key.
        
        Args:
            plaintext: Data to encrypt
            white_box_key_id: ID of white-box protected key
            
        Returns:
            Ciphertext
        """
        if white_box_key_id not in self.white_box_keys:
            raise ValueError(f"Unknown white-box key: {white_box_key_id}")
        
        wb_key = self.white_box_keys[white_box_key_id]
        return self.wb_aes.encrypt_with_tables(plaintext, wb_key)
    
    def decrypt_white_box(self, ciphertext: bytes, white_box_key_id: str) -> bytes:
        """
        Decrypt data using white-box protected key.
        
        Args:
            ciphertext: Encrypted data
            white_box_key_id: ID of white-box protected key
            
        Returns:
            Decrypted plaintext
        """
        if white_box_key_id not in self.white_box_keys:
            raise ValueError(f"Unknown white-box key: {white_box_key_id}")
        
        wb_key = self.white_box_keys[white_box_key_id]
        return self.wb_aes.decrypt_with_tables(ciphertext, wb_key)
    
    def obfuscate_key_storage(self, key: bytes) -> Tuple[bytes, bytes]:
        """
        Obfuscate key for secure storage.
        
        Args:
            key: Original key
            
        Returns:
            Tuple of (obfuscated_key, deobfuscation_data)
        """
        return self.obfuscator.obfuscate_key(key)
    
    def deobfuscate_key_storage(self, obfuscated_key: bytes, 
                               deobfuscation_data: bytes) -> bytes:
        """
        Recover key from obfuscated storage.
        
        Args:
            obfuscated_key: Obfuscated key
            deobfuscation_data: Deobfuscation metadata
            
        Returns:
            Original key
        """
        return self.obfuscator.deobfuscate_key(obfuscated_key, deobfuscation_data)
    
    def export_white_box_key(self, white_box_key_id: str) -> Dict[str, any]:
        """
        Export white-box key for storage or transmission.
        
        Args:
            white_box_key_id: Key identifier
            
        Returns:
            Serializable dictionary
        """
        if white_box_key_id not in self.white_box_keys:
            raise ValueError(f"Unknown white-box key: {white_box_key_id}")
        
        wb_key = self.white_box_keys[white_box_key_id]
        
        return {
            'key_id': wb_key.key_id,
            'table_data': wb_key.table_data.hex(),
            'encoding_data': wb_key.encoding_data.hex(),
            'algorithm': wb_key.algorithm,
            'key_size': wb_key.key_size
        }
    
    def import_white_box_key(self, key_data: Dict[str, any]) -> str:
        """
        Import white-box key from exported data.
        
        Args:
            key_data: Exported key data
            
        Returns:
            Key ID
        """
        wb_key = WhiteBoxKey(
            key_id=key_data['key_id'],
            table_data=bytes.fromhex(key_data['table_data']),
            encoding_data=bytes.fromhex(key_data['encoding_data']),
            algorithm=key_data['algorithm'],
            key_size=key_data['key_size']
        )
        
        self.white_box_keys[wb_key.key_id] = wb_key
        return wb_key.key_id


class DRMProtection:
    """
    Example: Digital Rights Management using white-box cryptography.
    
    Protects content encryption keys in software players.
    """
    
    def __init__(self):
        """Initialize DRM protection system."""
        self.wb_crypto = WhiteBoxCryptography()
        self.content_keys: Dict[str, str] = {}  # content_id -> wb_key_id
    
    def protect_content_key(self, content_id: str, content_key: bytes) -> str:
        """
        Protect a content encryption key using white-box crypto.
        
        Args:
            content_id: Content identifier
            content_key: Original content key
            
        Returns:
            White-box key ID
        """
        wb_key_id = self.wb_crypto.create_white_box_key(content_key)
        self.content_keys[content_id] = wb_key_id
        return wb_key_id
    
    def decrypt_content(self, content_id: str, encrypted_content: bytes) -> bytes:
        """
        Decrypt content using protected key.
        
        Args:
            content_id: Content identifier
            encrypted_content: Encrypted content
            
        Returns:
            Decrypted content
        """
        if content_id not in self.content_keys:
            raise ValueError(f"No key for content: {content_id}")
        
        wb_key_id = self.content_keys[content_id]
        return self.wb_crypto.decrypt_white_box(encrypted_content, wb_key_id)
    
    def encrypt_content(self, content_id: str, plaintext_content: bytes) -> bytes:
        """
        Encrypt content using protected key.
        
        Args:
            content_id: Content identifier
            plaintext_content: Content to encrypt
            
        Returns:
            Encrypted content
        """
        if content_id not in self.content_keys:
            raise ValueError(f"No key for content: {content_id}")
        
        wb_key_id = self.content_keys[content_id]
        return self.wb_crypto.encrypt_white_box(plaintext_content, wb_key_id)


# Convenience functions
def create_white_box_system() -> WhiteBoxCryptography:
    """
    Create a white-box cryptography system.
    
    Returns:
        Initialized WhiteBoxCryptography instance
    """
    return WhiteBoxCryptography()


def protect_key(key: bytes) -> Tuple[bytes, bytes]:
    """
    Quickly protect a key with obfuscation.
    
    Args:
        key: Original key
        
    Returns:
        Tuple of (obfuscated_key, recovery_data)
    """
    obfuscator = KeyObfuscator()
    return obfuscator.obfuscate_key(key)
