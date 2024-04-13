from Crypto.Cipher import AES

BLOCK_SIZE = AES.block_size
CIPHER_MODE = AES.MODE_CBC
INITIALIZATION_VECTOR = b'\xedZY\xda\xf6\xc3\x89\xb3\xc3\x1b\xf5\x9b\xac\xafQ\xd6'
KEY_SIZE = 4096
PRIVATE_KEY_NAME = "private_key.pem"
PUBLIC_EXPONENT = 65537
PUBLIC_KEY_NAME = "public_key.pem"
VOLUME_SERIAL_NUMBER = "C0008E5C"