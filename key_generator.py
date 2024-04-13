# Third-party library imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox

# Constants 
from constants import PRIVATE_KEY_NAME, PUBLIC_KEY_NAME, KEY_SIZE, PUBLIC_EXPONENT, CIPHER_MODE, BLOCK_SIZE, INITIALIZATION_VECTOR

def generate_keys():
    # Generation of private and public keys
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE
    )
    public_key = private_key.public_key()

    return private_key, public_key

def generate_keys_pem():
    private_key, public_key = generate_keys()
    
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

def encrypt_private_pem(pin, private_pem):
    # Creation a hash from the pin
    key = hashlib.sha256(pin.encode()).digest()
    # Making a cipher using the hash as a key
    cipher = AES.new(key, CIPHER_MODE, INITIALIZATION_VECTOR)
    # Encryption of the private key
    encrypted_private_key = cipher.encrypt(pad(private_pem, BLOCK_SIZE))

    return encrypted_private_key

def save_key(key, key_name):
    short_name = key_name[:-8]
    capitalized_name = short_name.capitalize()

    # Saving the file in user specified directory
    directory = filedialog.askdirectory(title=f"Select directory to save {short_name} key")
    if directory:
        with open(directory + "/" + key_name, "wb") as key_file:
            key_file.write(key)
        messagebox.showinfo("Success", f"{capitalized_name} key saved successfully.")
        return True
    else:
        messagebox.showwarning("Warning", f"No directory selected for {short_name} key.")
        return False

def generate_keys_button():
    private_pem, public_pem = generate_keys_pem()

    # Encryption of private key using hash of user's PIN
    pin = pin_entry.get()
    if pin == '':
        messagebox.showwarning("Warning", "No PIN entered!")
    else:
        encrypted_private_key = encrypt_private_pem(pin, private_pem)

        if save_key(encrypted_private_key, PRIVATE_KEY_NAME):
            save_key(public_pem, PUBLIC_KEY_NAME)
        else:
            return
        # Clear the PIN entry field
        pin_entry.delete(0, 'end')

if __name__ == "__main__":
    # GUI setup
    root = Tk()
    root.title("Key Generator")
    root.geometry("400x200")
    root.resizable(False, False)

    pin_label = Label(root, text="Enter a PIN:")
    pin_label.pack(pady=10)

    pin_entry = Entry(root, show="*")
    pin_entry.pack()

    generate_button = Button(root, text="Generate Keys", command=generate_keys_button)
    generate_button.pack(pady=20)

    root.mainloop()