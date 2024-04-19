from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime
import hashlib
from lxml import etree
import os
import time
import tkinter as tk
from tkinter import messagebox, filedialog
from constants import ALLOWED_EXSTENSIONS, BLOCK_SIZE, CIPHER_MODE, PRIVATE_KEY_NAME, PUBLIC_KEY_NAME


class EncryptionUtils:
    def __init__(self):
        self.drive_letter = ''
        self.root = ''

    def get_public_key(self):
        with open(PUBLIC_KEY_NAME, "rb") as key_file:
            try:
                public_key = serialization.load_pem_public_key(
                    key_file.read()
                )
                return public_key
            except:
                messagebox.showerror("Error", "Something is wrong with your public key!")
                return

    def get_private_key(self, private_key_path):
        with open(private_key_path, "rb") as key_file:
            private_pem = key_file.read()
            
        pin = self.get_pin()
        if not pin:
            messagebox.showwarning("Warning", "No PIN entered!")
            return
        
        try: 
            key = hashlib.sha256(pin.encode()).digest()
            # First BLOCK_SIZE amount of bytes of private_pem are the initialization vector
            cipher = AES.new(key, CIPHER_MODE, private_pem[:BLOCK_SIZE])
            decrypted_private_key = unpad(cipher.decrypt(private_pem[BLOCK_SIZE:]), BLOCK_SIZE)
        except Exception as e:
            messagebox.showerror("Error", "The provided PIN was probably incorrect: " + str(e))
            return
        try:
            private_key = serialization.load_pem_private_key(
                decrypted_private_key,
                password= None
            )
            return private_key
        except Exception as e:
            messagebox.showerror("Error", "Something is wrong with your private key: " + str(e))
            return

    def encrypt(self, data):
        public_key = self.get_public_key()
        if not public_key:
            return
        try:
            ciphertext = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            messagebox.showerror("Error", "Encryption failed: " + str(e))
            return

    def decrypt(self, ciphertext, private_key_path):
        private_key = self.get_private_key(private_key_path)
        if not private_key:
            return
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed: " + str(e))
            return   

    def sign(self, file_bytes, private_key_path):
        hash_of_file_bytes = hashlib.sha256(file_bytes).digest()
        private_key = self.get_private_key(private_key_path)
        if not private_key:
            return
        try:
            signature = private_key.sign(
                hash_of_file_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            messagebox.showerror("Error", "Signing failed: " + str(e))
            return   

    def verification(self, signature_file, verified_file):
        public_key = self.get_public_key()
        if not public_key:
            return False
        try:
            signature = self.get_document_hash_from_xml(signature_file)
            message = hashlib.sha256(verified_file.read()).digest()
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def create_xades(self, file, private_key_path):
        file_bytes = file.read()
        document_hash = self.sign(file_bytes, private_key_path)
        if document_hash:
            username = os.environ.get('USERNAME')
            email = username + '@gmail.com'

            root = etree.Element("Signature")
            document_info = etree.SubElement(root, "DocumentInfo")
            etree.SubElement(document_info, "Name").text = os.path.basename(file.name)
            etree.SubElement(document_info, "Size").text = str(len(file_bytes))
            etree.SubElement(document_info, "Extension").text = os.path.splitext(file.name)[1]
            etree.SubElement(document_info, "ModifiedDate").text = time.strftime("%d-%m-%Y %H:%M:%S", time.localtime(os.path.getmtime(file.name)))

            signing_user = etree.SubElement(root, "SigningUser")
            etree.SubElement(signing_user, "Name").text = username
            etree.SubElement(signing_user, "Email").text = email
            etree.SubElement(signing_user, "Timestamp").text = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            etree.SubElement(root, "DocumentHash").text = document_hash

            signature_xml = etree.tostring(root, pretty_print=True)

            return signature_xml
        else:
            return

    def sign_file(self):
        private_key_path = os.path.join(self.drive_letter, PRIVATE_KEY_NAME)
        if not self.check_key_existence(private_key_path):
            return

        chosen_file = self.select_file("Choose file to sign.", ALLOWED_EXSTENSIONS, None)
        if not chosen_file:
            return
        
        signature_bytes = self.create_xades(chosen_file, private_key_path)
        if not signature_bytes:
            return
        
        file_name = os.path.basename(chosen_file.name).replace('.','_') + "_signature"
        signature_file_path = self.save_file_dialog(".xml", file_name, [("XML files","*.xml")])
        if not signature_file_path:
            return
        
        self.write_file(signature_file_path, signature_bytes, "The signature file has been saved.")

    def get_document_hash_from_xml(self, xml_file):
        xml_string = xml_file.read().decode()
        root = etree.fromstring(xml_string)
        document_hash = root.find("DocumentHash")
        document_hash_bytes = bytes.fromhex(document_hash.text)

        return document_hash_bytes

    def verify_signature(self):
        if not self.check_key_existence(PUBLIC_KEY_NAME):
            return
        
        signature_file = self.select_file("Choose signature to verify", ".xml", "Invalid file type selected!\nExpected: .xml")
        if not signature_file:
            return
        
        verified_file = self.select_file("Choose file to verify with the signature.", ALLOWED_EXSTENSIONS, None)
        if not verified_file:
            return
        
        if self.verification(signature_file, verified_file):
            messagebox.showinfo("Verification Success", "Verification of the signature was successful.")
        else:
            messagebox.showinfo("Verification Failed", "Signature can't be verified.")

    def invalid_file_type_message(self):
        extensions_formatted = ", ".join(ALLOWED_EXSTENSIONS)
        message = "Invalid file type selected!\nExpected one of the following file types: {}".format(extensions_formatted)
        messagebox.showerror("Error", message)

    def get_pin(self):
        pin_window = tk.Toplevel(self.root)
        pin_window.title("Enter PIN")
        pin_window.geometry("400x200")
        pin_window.resizable(False, False)
        pin_window.focus_set()

        pin_label = tk.Label(pin_window, text="Enter the PIN:")
        pin_label.pack(pady=10)

        pin_entry = tk.Entry(pin_window, show="*")
        pin_entry.pack()

        pin = None
        def on_ok():
            nonlocal pin
            pin = pin_entry.get()
            pin_window.destroy()

        generate_button = tk.Button(pin_window, text="OK", command=on_ok)
        generate_button.pack(pady=20)

        pin_window.wait_window(pin_window)
        return pin

    def select_file_dialog(self, title):
        file = filedialog.askopenfile(
            mode="rb",
            title=title,
        )
        if not file:
            messagebox.showerror("Error", "No file selected!")
        return file

    def save_file_dialog(self, defaultextension, initialfile, filetypes):
        file_path = filedialog.asksaveasfilename(
            title="Save As",
            defaultextension=defaultextension,
            initialfile=initialfile,
            filetypes=filetypes
        )
        if not file_path:
            messagebox.showerror("Error", "File wasn't saved!")
        return file_path

    def check_key_existence(self, key_path):
        if not os.path.exists(key_path):
            messagebox.showerror("Error", f"Can't find at {key_path}!")
            return False
        return True

    def select_file(self, message, file_type, warning_message):
        file = self.select_file_dialog(message)
        if not file:
            return
        if not file.name.endswith(file_type):
            if warning_message:
                messagebox.showerror("Error", warning_message)
            else:
                self.invalid_file_type_message()
            return
        return file

    def write_file(self, file_path, data, message):
        with open(file_path, 'wb') as file:
            file.write(data)
        messagebox.showinfo("Information", message)

    def encrypt_file(self):
        if not self.check_key_existence(PUBLIC_KEY_NAME):
            return
        
        chosen_file = self.select_file("Choose file to encrypt.", ALLOWED_EXSTENSIONS, None)        
        if not chosen_file:
            return
        
        file_bytes = chosen_file.read()
        encrypted_bytes = self.encrypt(file_bytes)
        if not encrypted_bytes:
            return
        
        file_name = os.path.basename(chosen_file.name).replace('.','_')
        encrypted_file_path = self.save_file_dialog(".enc", file_name, [("Encrypted files","*.enc")])
        if not encrypted_file_path:
            return
        
        self.write_file(encrypted_file_path, encrypted_bytes, "The encrypted file has been saved.")

    def decrypt_file(self):
        private_key_path = os.path.join(self.drive_letter, PRIVATE_KEY_NAME)
        if not self.check_key_existence(private_key_path):
            return
                
        encrypted_file = self.select_file("Choose file to decrypt.", ".enc", "Invalid file type selected!\nExpected: .enc")
        if not encrypted_file:
            return
        
        file_bytes = encrypted_file.read()
        decrypted_bytes = self.decrypt(file_bytes, private_key_path)
        if not decrypted_bytes:
            return
        
        name_parts = os.path.basename(encrypted_file.name)[:-4].rsplit('_', 1)
        file_name = '.'.join(name_parts)
        decrypted_file_path = self.save_file_dialog('', file_name, [("C++ Source","*.cpp"), ("JSON Source File","*.json"), ("SQL Source File","*.sql"), ("Text Document","*.txt")] )
        if not decrypted_file_path:
            return
                             
        self.write_file(decrypted_file_path, decrypted_bytes, "The decrypted file has been saved.")