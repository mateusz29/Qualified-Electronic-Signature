from Crypto.Cipher import AES

VOLUME_SERIAL_NUMBER = "C0008E5C"
PRIVATE_KEY_NAME = "private_key.pem"
PUBLIC_KEY_NAME = "public_key.pem"
KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537
CIPHER_MODE = AES.MODE_CBC
BLOCK_SIZE = AES.block_size
INITIALIZATION_VECTOR = b'\xedZY\xda\xf6\xc3\x89\xb3\xc3\x1b\xf5\x9b\xac\xafQ\xd6'