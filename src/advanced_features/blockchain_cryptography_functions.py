

import hashlib
import time

class BlockchainCryptographyFunctions:
    def __init__(self):
        pass

    def calculate_block_hash(self, index: int, timestamp: float, data: str, previous_hash: str, nonce: int) -> str:
        """Calculates the hash for a blockchain block."""
        block_string = f"{index}{timestamp}{data}{previous_hash}{nonce}"
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def proof_of_work(self, last_proof: int) -> int:
        """Simple Proof of Work algorithm: Find a number p' such that hash(pp') contains 4 leading zeros."""
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    def valid_proof(self, last_proof: int, proof: int) -> bool:
        """Validates the proof of work."""
        guess = f"{last_proof}{proof}".encode("utf-8")
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def create_transaction_hash(self, sender: str, recipient: str, amount: float) -> str:
        """Creates a hash for a transaction."""
        transaction_string = f"{sender}{recipient}{amount}{time.time()}"
        return hashlib.sha256(transaction_string.encode("utf-8")).hexdigest()


