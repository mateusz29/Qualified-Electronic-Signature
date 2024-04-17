from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
from constants import BLOCK_SIZE, CIPHER_MODE, KEY_SIZE, PUBLIC_EXPONENT


class KeyGenerator:
    def generate_keys(self):
        # Generation of private and public keys
        private_key = rsa.generate_private_key(
            public_exponent=PUBLIC_EXPONENT,
            key_size=KEY_SIZE
        )
        public_key = private_key.public_key()

        return private_key, public_key

    def serialize_keys(self, private_key, public_key):
        # Convertion of private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Convertion of public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    def encrypt_private_pem(self, pin, private_pem):
        # Creation and decrytpion of private key
        key = hashlib.sha256(pin.encode()).digest()
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(key, CIPHER_MODE, iv)
        encrypted_private_key = cipher.encrypt(pad(private_pem, BLOCK_SIZE))

        return iv + encrypted_private_key
