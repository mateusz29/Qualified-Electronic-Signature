# Standard library imports
from datetime import datetime
import os
import threading
import time

# Third-party library imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
from lxml import etree
from PIL import Image, ImageTk
import pythoncom
from tkinter import Tk, Label, messagebox, Button, Entry, Toplevel, filedialog, Frame, StringVar
import wmi

# Constants and global variables
from constants import BLOCK_SIZE, CIPHER_MODE, PRIVATE_KEY_NAME, PUBLIC_KEY_NAME, VOLUME_SERIAL_NUMBER
drive_letter = ''

def get_public_key():
    with open(PUBLIC_KEY_NAME, "rb") as key_file:
        try:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        except:
            messagebox.showerror("Error", "Something is wrong with your public key!")
            return
    return public_key

def get_private_key(private_key_path):
    with open(private_key_path, "rb") as key_file:
        private_pem = key_file.read()
        
    pin = get_pin()
    if pin == '' or pin == None:
        messagebox.showwarning("Warning", "No PIN entered!")
        return
    else:
        try: 
            key = hashlib.sha256(pin.encode()).digest()
            # First BLOCK_SIZE amount of bytes are the initialization vector
            cipher = AES.new(key, CIPHER_MODE, private_pem[:BLOCK_SIZE])
            decrypted_private_key = unpad(cipher.decrypt(private_pem[BLOCK_SIZE:]), BLOCK_SIZE)
        except Exception as e:
            messagebox.showerror("Error", str(e) + "\nThe provided PIN was probably incorrect!")
            return

        private_key = serialization.load_pem_private_key(
            decrypted_private_key,
            password= None
        )

        return private_key

def encrypt(data):
    public_key = get_public_key()
    if public_key:
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    else:
        return

def decrypt(ciphertext, private_key_path):
    private_key = get_private_key(private_key_path)
    if private_key:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    else:
        return

def sign(file_bytes, private_key_path):
    hash_of_file_bytes = hashlib.sha256(file_bytes).digest()
    private_key = get_private_key(private_key_path)
    if private_key:
        signature = private_key.sign(
            hash_of_file_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature.hex()
    else:
        return

def create_xades(file, private_key_path):
    file_bytes = file.read()
    document_hash = sign(file_bytes, private_key_path)
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

def sign_file():
    private_key_path = os.path.join(drive_letter, PRIVATE_KEY_NAME)
    if os.path.exists(private_key_path):
        file = filedialog.askopenfile(
            mode="rb",
            title="Choose file to sign.",
            filetypes=[
                ("All files","*.*"),
                ("C++ Source","*.cpp"),
                ("JSON Source File","*.json"),
                ("SQL Source File","*.sql"),
                ("Text Document","*.txt")                
            ]
        )

        if file is None:
            messagebox.showwarning("Warning", "No file selected!")
            return
        
        allowed_extensions = (".cpp",".json",".sql",".txt")
        if file.name.lower().endswith(allowed_extensions):
            signature_bytes = create_xades(file, private_key_path)
            if signature_bytes:
                file_name = os.path.basename(file.name).replace('.','_')
                signature_file_path = filedialog.asksaveasfilename(
                    title="Save Signature As",
                    defaultextension=".xml",
                    initialfile=file_name + "_signature",
                    filetypes=[("XML files","*.xml")]
                )

                if signature_file_path == "":
                    messagebox.showwarning("Warning", "File wasn't saved!")
                    return

                with open(signature_file_path, 'wb') as file:
                    file.write(signature_bytes)

                messagebox.showinfo("Information", "The signature file has been saved.")
            else:
                return
        else:
            messagebox.showwarning("Warning", "Invalid file type selected!")
    else:
        messagebox.showerror("Error", "Drive isn't connected!")
        return

def get_document_hash_xml(xml_file):
    xml_string = xml_file.read().decode()
    root = etree.fromstring(xml_string)
    document_hash = root.find("DocumentHash")
    document_hash_bytes = bytes.fromhex(document_hash.text)

    return document_hash_bytes

def verification(signature_file, verified_file):
    public_key = get_public_key()
    if public_key == None:
        return False
    try:
        signature = get_document_hash_xml(signature_file)
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

def verify_signature():
    if os.path.exists(PUBLIC_KEY_NAME):
        signature_file = filedialog.askopenfile(
            mode="rb",
            title="Choose signature to verify.",
            filetypes=[
                ("All files","*.*"),
                ("XML files","*.xml")
            ]
        )

        if signature_file is None:
            messagebox.showwarning("Warning", "No file selected!")
            return
        
        allowed_extensions = (".xml",)
        if signature_file.name.lower().endswith(allowed_extensions):
            verified_file = filedialog.askopenfile(
                mode="rb",
                title="Choose file to verify with the signature.",
                filetypes=[
                    ("All files","*.*"),
                    ("C++ Source","*.cpp"),
                    ("JSON Source File","*.json"),
                    ("SQL Source File","*.sql"),
                    ("Text Document","*.txt")  
                ]
            )

            if verified_file is None:
                messagebox.showwarning("Warning", "No file selected!")
                return

            allowed_extensions = (".cpp",".json",".sql",".txt")
            if verified_file.name.lower().endswith(allowed_extensions):
                if verification(signature_file, verified_file):
                    messagebox.showinfo("Verification Success", "Verification of the signature was successful.")
                else:
                    messagebox.showinfo("Verification Failed", "Signature can't be verified.")
            else:
                extensions_formatted = ", ".join(allowed_extensions)
                message = "Invalid file type selected! \nExpected one of the following file types: {}".format(extensions_formatted)
                messagebox.showerror("Error", message)
        else:
            messagebox.showwarning("Warning", "Invalid file type selected! \nExpected a xml file.")
    else:
        messagebox.showerror("Error", "Can't find public key!")
        return

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

def encrypt_file():
    if os.path.exists(PUBLIC_KEY_NAME):
        file = filedialog.askopenfile(
            mode="rb",
            title="Choose file to encrypt.",
            filetypes=[
                ("All files","*.*"),
                ("C++ Source","*.cpp"),
                ("JSON Source File","*.json"),
                ("SQL Source File","*.sql"),
                ("Text Document","*.txt")                
            ]
        )

        if file is None:
            messagebox.showwarning("Warning", "No file selected!")
            return
        
        allowed_extensions = (".cpp",".json",".sql",".txt")
        if file.name.lower().endswith(allowed_extensions):
            file_bytes = file.read()
            encrypted_bytes = encrypt(file_bytes)
            if encrypted_bytes:
                file_name = os.path.basename(file.name).replace('.','_')
                encrypted_file_path = filedialog.asksaveasfilename(
                    title="Save As",
                    defaultextension=".enc",
                    initialfile=file_name,
                    filetypes=[("Encrypted files","*.enc")]
                )

                if encrypted_file_path == "":
                    messagebox.showwarning("Warning", "File wasn't saved!")
                    return

                with open(encrypted_file_path, 'wb') as file:
                    file.write(encrypted_bytes)

                messagebox.showinfo("Information", "The encrypted file has been saved.")
            else:
                return
        else:
            messagebox.showwarning("Warning", "Invalid file type selected!")
    else:
        messagebox.showerror("Error", "Can't find public key!")
        return

def decrypt_file():
    private_key_path = os.path.join(drive_letter, PRIVATE_KEY_NAME)
    if os.path.exists(private_key_path):
        file = filedialog.askopenfile(mode="rb", title="Choose file to decrypt.")
        if file is None:
            messagebox.showwarning("Warning", "No file selected!")
            return
        
        file_bytes = file.read()
        decrypted_bytes = decrypt(file_bytes, private_key_path)
        if decrypted_bytes:
            name_parts = os.path.basename(file.name)[:-4].rsplit('_', 1)
            file_name = '.'.join(name_parts)
            decrypted_file_path = filedialog.asksaveasfilename(
                title="Save As",
                initialfile=file_name,
                filetypes=[
                    ("All files","*.*"),
                    ("Text Document","*.txt"),
                    ("C++ Source","*.cpp")
                ]
            )

            if decrypted_file_path == "":
                messagebox.showwarning("Warning", "File wasn't saved!")
                return

            with open(decrypted_file_path, 'wb') as file:
                file.write(decrypted_bytes)
            
            messagebox.showinfo("Information", "The decrypted file has been saved.")
        else:
            return
    else:
        messagebox.showerror("Error", "Drive isn't connected!")
        return

def is_pendrive_connected():
    c = wmi.WMI()
    global drive_letter
    for volume in c.Win32_LogicalDisk(DriveType=2):
        if volume.VolumeSerialNumber == VOLUME_SERIAL_NUMBER:
            drive_letter = volume.DeviceID
            return True
    drive_letter = ''
    return False

def update_status():
    pythoncom.CoInitialize()
    try:
        while True:    
            is_connected = is_pendrive_connected()
            if is_connected:
                status_icon.config(image=connected_icon)
            else:
                status_icon.config(image=disconnected_icon)
            time.sleep(1)
    finally:
        pythoncom.CoUninitialize()

if __name__ == "__main__":
    root = Tk()
    root.title("Main App")
    root.geometry("500x400")
    root.resizable(False, False)

    # Loading the images
    connected_image = Image.open("icons/usb_connected.png")
    disconnected_image = Image.open("icons/usb_disconnected.png")
    connected_image = connected_image.resize((50, 50), Image.Resampling.LANCZOS)
    disconnected_image = disconnected_image.resize((50, 50), Image.Resampling.LANCZOS)
    connected_icon = ImageTk.PhotoImage(connected_image)
    disconnected_icon = ImageTk.PhotoImage(disconnected_image)

    # Making a status bar
    status_text = StringVar()
    status_bar = Label(root, textvariable=status_text, anchor="s", font=("Arial", 14), wraplength=300)
    status_bar.grid(row=0, column=0, columnspan=2, sticky="EW", padx=20, pady=10)
    status_text.set("Application for encrypting, decrypting, signing and verificating")

    # Creation of a status icon label, line seperator and buttons
    status_icon = Label(root, image=disconnected_icon)
    status_icon.grid(row=0, column=1, sticky="E", padx=20, pady=20)
    separator = Frame(root, height=2, bg="gray")
    separator.grid(row=1, column=0, columnspan=2, sticky="EW", padx=10, pady=20)
    button_style = {"bg": "#9C27B0", "fg": "white", "font": ("Arial", 12), "width": 20, "padx": 10, "pady": 10}
    encrypt_button = Button(root, text="Encrypt File", command=encrypt_file, **button_style)
    decrypt_button = Button(root, text="Decrypt File", command=decrypt_file, **button_style)
    sign_document_button = Button(root, text="Sign Document", command=sign_file, **button_style)
    verify_signature_button = Button(root, text="Verify Signature", command=verify_signature, **button_style)
    encrypt_button.grid(row=2, column=0, sticky="EW", padx=20, pady=40)
    decrypt_button.grid(row=3, column=0, sticky="EW", padx=20)
    sign_document_button.grid(row=2, column=1, sticky="EW", padx=20, pady=40)
    verify_signature_button.grid(row=3, column=1, sticky="EW", padx=20)

    # Starting the update thread
    threading.Thread(target=update_status, daemon=True).start()

    root.mainloop()