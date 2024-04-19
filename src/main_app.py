from PIL import Image, ImageTk
import pythoncom
import threading
import time
import tkinter as tk
import wmi
from constants import VOLUME_SERIAL_NUMBER
from encryption_utils import EncryptionUtils


class MainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Main App")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        self.encryption_utils = EncryptionUtils()
        self.encryption_utils.root = root

        # Loading the images
        connected_image = Image.open("icons/usb_connected.png")
        disconnected_image = Image.open("icons/usb_disconnected.png")
        connected_image = connected_image.resize((50, 50), Image.Resampling.LANCZOS)
        disconnected_image = disconnected_image.resize((50, 50), Image.Resampling.LANCZOS)
        self.connected_icon = ImageTk.PhotoImage(connected_image)
        self.disconnected_icon = ImageTk.PhotoImage(disconnected_image)

        # Setting up a status bar
        self.text = tk.StringVar()
        self.bar = tk.Label(root, textvariable=self.text, anchor="s", font=("Arial", 14), wraplength=300)
        self.bar.grid(row=0, column=0, columnspan=2, sticky="EW", padx=20, pady=10)
        self.text.set("Application for encrypting, decrypting, signing and verificating")

        # Creating status icon label, line seperator and buttons
        self.status_icon = tk.Label(root, image=self.disconnected_icon)
        self.status_icon.grid(row=0, column=1, sticky="E", padx=20, pady=20)
        self.separator = tk.Frame(root, height=2, bg="gray")
        self.separator.grid(row=1, column=0, columnspan=2, sticky="EW", padx=10, pady=20)

        button_style = {"bg": "#9C27B0", "fg": "white", "font": ("Arial", 12), "width": 20, "padx": 10, "pady": 10}
        self.encrypt_button = tk.Button(root, text="Encrypt File", command=self.encryption_utils.encrypt_file, **button_style)
        self.decrypt_button = tk.Button(root, text="Decrypt File", command=self.encryption_utils.decrypt_file, **button_style)
        self.sign_document_button = tk.Button(root, text="Sign Document", command=self.encryption_utils.sign_file, **button_style)
        self.verify_signature_button = tk.Button(root, text="Verify Signature", command=self.encryption_utils.verify_signature, **button_style)

        self.encrypt_button.grid(row=2, column=0, sticky="EW", padx=20, pady=40)
        self.decrypt_button.grid(row=3, column=0, sticky="EW", padx=20)
        self.sign_document_button.grid(row=2, column=1, sticky="EW", padx=20, pady=40)
        self.verify_signature_button.grid(row=3, column=1, sticky="EW", padx=20)

        threading.Thread(target=self.update_status, daemon=True).start()

    def is_pendrive_connected(self):
        c = wmi.WMI()
        for volume in c.Win32_LogicalDisk(DriveType=2):  # Checking for removable devices (DriveType=2)
            if volume.VolumeSerialNumber == VOLUME_SERIAL_NUMBER:
                self.encryption_utils.drive_letter = volume.DeviceID
                return True
        self.encryption_utils.drive_letter = ''
        return False

    def update_status(self):
        pythoncom.CoInitialize()  # Have to do this to be able to use wmi in threads
        try:
            while True:    
                is_connected = self.is_pendrive_connected()
                if is_connected:
                    self.status_icon.config(image=self.connected_icon)
                else:
                    self.status_icon.config(image=self.disconnected_icon)
                time.sleep(1)
        except:
            pass
        finally:
            pythoncom.CoUninitialize()

if __name__ == "__main__":
    root = tk.Tk()
    app = MainApp(root)
    root.mainloop()