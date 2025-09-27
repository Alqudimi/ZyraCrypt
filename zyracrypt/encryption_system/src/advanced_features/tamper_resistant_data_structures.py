

import hashlib
from typing import List, Tuple

class TamperResistantDataStructures:
    def __init__(self):
        pass

    def create_hash_chain(self, data_list: List[bytes]) -> List[bytes]:
        """Creates a hash chain for a list of data blocks."""
        if not data_list:
            return []

        hash_chain = []
        previous_hash = b""
        for data_block in data_list:
            current_hash = hashlib.sha256(previous_hash + data_block).digest()
            hash_chain.append(current_hash)
            previous_hash = current_hash
        return hash_chain

    def verify_hash_chain(self, data_list: List[bytes], hash_chain: List[bytes]) -> bool:
        """Verifies a hash chain for a list of data blocks."""
        if len(data_list) != len(hash_chain):
            return False

        previous_hash = b""
        for i, data_block in enumerate(data_list):
            expected_hash = hashlib.sha256(previous_hash + data_block).digest()
            if expected_hash != hash_chain[i]:
                return False
            previous_hash = hash_chain[i]
        return True

    def create_merkle_tree(self, data_blocks: List[bytes]) -> List[bytes]:
        """Creates a Merkle tree (list of hashes) from data blocks."""
        if not data_blocks:
            return []

        # Hash all leaf nodes
        hashed_blocks = [hashlib.sha256(block).digest() for block in data_blocks]

        # Build the tree upwards
        tree_level = hashed_blocks
        while len(tree_level) > 1:
            next_level = []
            for i in range(0, len(tree_level), 2):
                left = tree_level[i]
                right = tree_level[i+1] if i+1 < len(tree_level) else left # Handle odd number of leaves
                next_level.append(hashlib.sha256(left + right).digest())
            tree_level = next_level
        return tree_level # The root hash is the last element

    def get_merkle_root(self, data_blocks: List[bytes]) -> bytes:
        """Returns the Merkle root hash for a list of data blocks."""
        tree = self.create_merkle_tree(data_blocks)
        return tree[0] if tree else b""

    def verify_merkle_proof(self, data_block: bytes, merkle_root: bytes, proof: List[Tuple[bytes, str]]) -> bool:
        """Verifies a Merkle proof for a single data block.
        Proof is a list of (hash, position) tuples, where position is 'left' or 'right'.
        This is a simplified placeholder; a full implementation requires generating the proof path.
        """
        current_hash = hashlib.sha256(data_block).digest()

        for proof_hash, position in proof:
            if position == 'left':
                current_hash = hashlib.sha256(proof_hash + current_hash).digest()
            elif position == 'right':
                current_hash = hashlib.sha256(current_hash + proof_hash).digest()
            else:
                return False # Invalid position
        
        return current_hash == merkle_root


