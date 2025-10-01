

from cryptography.hazmat.primitives.asymmetric import ec, rsa, dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class KeyExchange:
    def __init__(self):
        pass

    def generate_ecdh_key_pair(self, curve=ec.SECP256R1()) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generates an ECDH key pair."""
        private_key = ec.generate_private_key(
            curve,
            default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_shared_secret_ecdh(self, private_key: ec.EllipticCurvePrivateKey, peer_public_key: ec.EllipticCurvePublicKey, length: int = 32) -> bytes:
        """Derives a shared secret using ECDH."""
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

    def generate_dh_parameters(self, prime_length: int = 2048) -> dh.DHParameters:
        """Generates Diffie-Hellman parameters."""
        parameters = dh.generate_parameters(generator=2, key_size=prime_length, backend=default_backend())
        return parameters

    def generate_dh_key_pair(self, parameters: dh.DHParameters) -> tuple[dh.DHPrivateKey, dh.DHPublicKey]:
        """Generates a Diffie-Hellman key pair from parameters."""
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def derive_shared_secret_dh(self, private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey, length: int = 32) -> bytes:
        """Derives a shared secret using Diffie-Hellman."""
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key


