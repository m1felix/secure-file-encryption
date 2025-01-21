# Secure File Encryption Tool

## Overview

The **Secure File Encryption Tool** is a Python-based tool designed to provide strong encryption for files. Using AES (Advanced Encryption Standard) encryption, this tool helps protect sensitive data by ensuring it remains secure from unauthorized access. 

It allows users to:
- Encrypt files using a password-derived encryption key.
- Decrypt files back to their original form using the correct password.

This tool is essential in cybersecurity for safeguarding personal and confidential files in a world where data breaches and unauthorized access are increasingly common.

## Features
- **File Encryption**: Encrypts any file using AES encryption and saves the encrypted file with a `.enc` extension.
- **File Decryption**: Decrypts files that have been previously encrypted by the tool.
- **Password-based Security**: Encryption keys are derived from the user-provided password for added security.
- **CBC Mode**: Uses the AES Cipher Block Chaining (CBC) mode for encryption, making the encryption more secure.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/m1felix/secure-file-encryption.git
   cd secure-file-encryption
