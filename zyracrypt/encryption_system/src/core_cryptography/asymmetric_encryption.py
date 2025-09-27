
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class AsymmetricEncryption:
    def __init__(self):
        pass

    def generate_rsa_key_pair(self, public_exponent: int = 65537, key_size: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_rsa_oaep(self, public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_rsa_oaep(self, private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def generate_ecc_key_pair(self, curve=ec.SECP256R1()) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_ecc(self, private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_ecc(self, public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False



