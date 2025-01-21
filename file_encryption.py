from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from getpass import getpass
import os

# Encrypt a file
def encrypt_file(file_path, password):
    key = password.encode()[:16]  # AES requires a 16-byte key
    cipher = AES.new(key, AES.MODE_CBC)
    
    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    
    # Save the IV and the encrypted data in a new file
    with open(file_path + ".enc", 'wb') as enc_file:
        enc_file.write(cipher.iv)  # Store the IV at the beginning
        enc_file.write(encrypted_data)

    print(f"File '{file_path}' encrypted successfully!")

# Decrypt a file
def decrypt_file(file_path, password):
    key = password.encode()[:16]
    
    with open(file_path, 'rb') as enc_file:
        iv = enc_file.read(16)  # Read the IV from the beginning
        encrypted_data = enc_file.read()

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Save the decrypted data to a new file
    decrypted_file_path = file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    print(f"File '{file_path}' decrypted successfully to '{decrypted_file_path}'!")

# Main function
def main():
    print("Secure File Encryption Tool")
    print("1. Encrypt file")
    print("2. Decrypt file")
    choice = input("Enter your choice: ")

    if choice == "1":
        file_path = input("Enter the file path to encrypt: ")
        password = getpass("Enter encryption password: ")

        if os.path.exists(file_path):
            encrypt_file(file_path, password)
        else:
            print("Error: File does not exist.")
    elif choice == "2":
        file_path = input("Enter the file path to decrypt: ")
        password = getpass("Enter decryption password: ")

        if os.path.exists(file_path):
            decrypt_file(file_path, password)
        else:
            print("Error: File does not exist.")
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()

