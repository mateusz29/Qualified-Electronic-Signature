from tkinter import Tk, Label, messagebox, Button, Toplevel, Entry
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import wmi
import os

VOLUME_SERIAL_NUMBER = "C0008E5C"
PRIVATE_KEY_NAME = "private_key.pem"
PUBLIC_KEY_NAME = "public_key.pem"
KEY_SIZE = 4096
PUBLIC_EXPONENT = 65537
CIPHER_MODE = AES.MODE_CBC
BLOCK_SIZE = AES.block_size
INITIALIZATION_VECTOR = b'\xedZY\xda\xf6\xc3\x89\xb3\xc3\x1b\xf5\x9b\xac\xafQ\xd6'


def encrypt(data):
    with open(PUBLIC_KEY_NAME, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt(ciphertext):
    with open(PRIVATE_KEY_NAME, "rb") as key_file:
        private_pem = key_file.read()
        
    pin = get_pin()
    if pin == '' or pin == None:
        messagebox.showwarning("Warning", "No PIN entered!")
    else: 
        key = hashlib.sha256(pin.encode()).digest()        
        cipher = AES.new(key, CIPHER_MODE, INITIALIZATION_VECTOR)
        decrypted_private_key = unpad(cipher.decrypt(private_pem), BLOCK_SIZE)

        private_key = serialization.load_pem_private_key(
            decrypted_private_key,
            password= None
        )

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext

def get_pin():
    pin_window = Toplevel(root)
    pin_window.title("Enter PIN")
    pin_window.geometry("400x200")
    pin_window.resizable(False, False)
    pin_window.focus_set()

    pin_label = Label(pin_window, text="Enter the PIN:")
    pin_label.pack(pady=10)

    pin_entry = Entry(pin_window, show="*")
    pin_entry.pack()

    pin = None
    def on_ok():
        nonlocal pin
        pin = pin_entry.get()
        pin_window.destroy()

    generate_button = Button(pin_window, text="OK", command=on_ok)
    generate_button.pack(pady=20)

    pin_window.wait_window(pin_window)
    return pin


if __name__ == "__main__":

    print(PRIVATE_KEY_NAME[:-8])
    print(PUBLIC_KEY_NAME[:-8])

    root = Tk()
    root.title("Main app")
    root.geometry("500x300")

    # with open(PRIVATE_KEY_NAME, "rb") as key_file:
    #     private_pem = key_file.read()

    # pin = "1234"
    # key = hashlib.sha256(pin.encode()).digest()        
    # cipher = AES.new(key, CIPHER_MODE, INITIALIZATION_VECTOR)
    # decrypted_private_key = unpad(cipher.decrypt(private_pem), BLOCK_SIZE)

    # private_key = serialization.load_pem_private_key(
    #     decrypted_private_key,
    #     password= None
    # )

    # message = b"A message I want to sign"
    # signature = private_key.sign(
    #     message,
    #     padding.PSS(
    #         mgf=padding.MGF1(hashes.SHA256()),
    #         salt_length=padding.PSS.MAX_LENGTH
    #     ),
    #     hashes.SHA256()
    # )

    # #print(signature)
    # print(encrypt(message))

