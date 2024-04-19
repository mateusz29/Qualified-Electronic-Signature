import tkinter as tk
from tkinter import messagebox, filedialog
from key_generator import KeyGenerator
from constants import PRIVATE_KEY_NAME, PUBLIC_KEY_NAME


class KeyGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Key Generator")
        self.root.geometry("400x200")
        self.root.resizable(False, False)

        self.generator = KeyGenerator()

        self.pin_label = tk.Label(self.root, text="Enter a PIN:")
        self.pin_label.pack(pady=20)
        
        self.pin_entry = tk.Entry(self.root, show="*")
        self.pin_entry.pack()

        button_style = {"bg": "#9C27B0", "fg": "white", "font": ("Arial", 10)}
        self.generate_button = tk.Button(self.root, text="Generate Keys", command=self.generate_keys_button_click, **button_style)
        self.generate_button.pack(pady=20)
    
    def generate_keys_button_click(self):
        private_key, public_key = self.generator.generate_keys()
        private_pem, public_pem = self.generator.serialize_keys(private_key, public_key)

        # Encryption of private key using hash of user's PIN
        pin = self.pin_entry.get()
        if pin == '':
            messagebox.showwarning("Warning", "No PIN entered!")
        else:
            encrypted_private_key = self.generator.encrypt_private_pem(pin, private_pem)
            self.save_key(encrypted_private_key, PRIVATE_KEY_NAME)
            self.save_key(public_pem, PUBLIC_KEY_NAME)

            # Clear the PIN entry field
            self.pin_entry.delete(0, 'end')

    def save_key(self, key, key_name):
        # Need to remove the '_key.pem' from the name 
        short_name = key_name[:-8]
        capitalized_name = short_name.capitalize()

        # Saving the file in user specified directory
        directory = filedialog.askdirectory(title=f"Select directory to save {short_name} key", mustexist=True)
        if directory:
            with open(directory + "/" + key_name, "wb") as key_file:
                key_file.write(key)
            messagebox.showinfo("Success", f"{capitalized_name} key saved successfully.")
            return True
        else:
            messagebox.showerror("Saving error", f"No directory selected for {short_name} key.\nKey wasn't saved.")
            return False

if __name__ == '__main__':
    root = tk.Tk()
    app = KeyGeneratorApp(root)
    root.mainloop()