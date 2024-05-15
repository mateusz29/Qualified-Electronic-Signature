# Qualified Electronic Signature Emulator

## Overview

This project is developed as part of the Security of Computer Systems course. The main goal is to create a software tool for emulating a qualified electronic signature. The tool supports signing documents and performing basic encryption and decryption operations.

## Features

- **Document Signing**: Emulate the process of digitally signing documents using RSA keys.
- **Signature Verification**: Verify the signature of signed documents.
- **Encryption/Decryption**: Basic encryption and decryption operations using RSA and AES algorithms.
- **Key Management**: Generation and management of RSA keys, with the private key encrypted using AES and a user-defined PIN.

## Prerequisites

- Python 3.x
- Required libraries: `cryptography`, `pycryptodome`, `tkinter`, `Pillow`, `wmi`, `lxml`

## File Structure

- **constants.py**: Defines constants used across the application.
- **encryption_utils.py**: Contains the `EncryptionUtils` class which provides methods for encryption, decryption, signing, and verification of files.
- **main_app.py**: The main GUI application for using the encryption and signing features.
- **key_generator.py**: Contains the `KeyGenerator` class for generating and managing RSA keys.
- **key_generator_app.py**: A secondary application for generating RSA keys and encrypting the private key.

## Setup and Usage

### 1. Key Generation

Before using the main application, generate RSA keys for the user. This is done using the `key_generator_app.py`.

- Run the key generator application:
  ```sh
  python key_generator_app.py
- Enter a PIN when prompted. The keys will be saved in the selected directory with the private key encrypted using AES and the entered PIN.

### 2. Main Application

Use the main application to encrypt, decrypt, sign, and verify documents.

- Run the main application:
  ```sh
  python main_app.py
- Connect a USB drive with the required volume serial number specified in constants.py.
- The main window provides options to encrypt files, decrypt files, sign documents, and verify signatures.