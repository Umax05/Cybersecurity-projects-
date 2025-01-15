import os
import sys
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from getpass import getpass
import secrets

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secret key from the given password and salt using PBKDF2HMAC.
    The derived key is compatible with Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),      # SHA256 hashing algorithm
        length=32,                      # Fernet requires 32-byte keys
        salt=salt,                      # Salt
        iterations=100000,              # Number of iterations
        backend=default_backend()       # Backend
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path: str, password: str, remove_original: bool = False) -> None:
    """
    Encrypts the file at the given path using the provided password.
    The encrypted file will have a '.enc' extension.
    The salt is prepended to the encrypted data.
    If remove_original is True, deletes the original file after encryption.
    """
    try:
        # Generate a random 16-byte salt
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)

        # Read the original file data
        with open(file_path, 'rb') as file:
            original_data = file.read()

        # Encrypt the data
        encrypted_data = fernet.encrypt(original_data)

        # Prepend the salt to the encrypted data
        encrypted_data_with_salt = salt + encrypted_data

        # Define the encrypted file path
        encrypted_file_path = file_path + '.enc'

        # Write the encrypted data to the new file
        with open(encrypted_file_path, 'wb') as enc_file:
            enc_file.write(encrypted_data_with_salt)

        # Optionally remove the original file
        if remove_original:
            os.remove(file_path)

        # **Corrected Print Statement Below**
        print(f"✅ File encrypted successfully!\nEncrypted file saved as '{os.path.basename(encrypted_file_path)}'.\n")

    except FileNotFoundError:
        print("❌ Error: The file was not found. Please check the file path and try again.")
    except PermissionError:
        print("❌ Error: Permission denied. Ensure you have the necessary permissions to read/write the file.")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")

def decrypt_file(encrypted_file_path: str, password: str, remove_encrypted: bool = False) -> None:
    """
    Decrypts the file at the given path using the provided password.
    Assumes the file has a '.enc' extension and removes it after decryption if specified.
    """
    try:
        # Read the encrypted data
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data_with_salt = enc_file.read()

        # Check if the file is long enough to contain a salt
        if len(encrypted_data_with_salt) < 16:
            print("❌ Error: The encrypted file is corrupted or incomplete.")
            return

        # Extract the salt (first 16 bytes)
        salt = encrypted_data_with_salt[:16]
        encrypted_data = encrypted_data_with_salt[16:]

        # Derive the key using the extracted salt and provided password
        key = derive_key(password, salt)
        fernet = Fernet(key)

        # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)

        # Define the decrypted file path by removing the '.enc' extension
        if encrypted_file_path.endswith('.enc'):
            decrypted_file_path = encrypted_file_path[:-4]
        else:
            decrypted_file_path = encrypted_file_path + '.dec'

        # Write the decrypted data to the new file
        with open(decrypted_file_path, 'wb') as dec_file:
            dec_file.write(decrypted_data)

        # Optionally remove the encrypted file
        if remove_encrypted:
            os.remove(encrypted_file_path)

        print(f"✅ File decrypted successfully!\nDecrypted file saved as '{os.path.basename(decrypted_file_path)}'.\n")

    except FileNotFoundError:
        print("❌ Error: The encrypted file was not found. Please check the file path and try again.")
    except PermissionError:
        print("❌ Error: Permission denied. Ensure you have the necessary permissions to read/write the file.")
    except Exception as e:
        print("❌ Decryption failed. Please ensure that the password is correct and the file is not corrupted.")
        print(f"❌ Error Details: {e}")

def main():
    while True:
        print("\n🔒 File Encryption Tool")
        print("------------------------")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input("👉 Enter your choice (1/2/3): ").strip()

        if choice == '1':
            file_path = input("📁 Enter the full path of the file to encrypt: ").strip()

            if not os.path.isfile(file_path):
                print("❌ Error: The specified file does not exist. Please try again.")
                continue

            password = getpass("🔑 Enter a password for encryption: ")
            confirm_password = getpass("🔑 Confirm password: ")

            if password != confirm_password:
                print("❌ Error: Passwords do not match. Please try again.")
                continue

            if not password:
                print("❌ Error: Password cannot be empty. Please try again.")
                continue

            encrypt_choice = input("🗑️ Do you want to delete the original file after encryption? (y/n): ").strip().lower()
            remove_original = encrypt_choice == 'y'

            encrypt_file(file_path, password, remove_original)

        elif choice == '2':
            encrypted_file_path = input("📁 Enter the full path of the file to decrypt: ").strip()

            if not os.path.isfile(encrypted_file_path):
                print("❌ Error: The specified encrypted file does not exist. Please try again.")
                continue

            password = getpass("🔑 Enter your password for decryption: ")

            if not password:
                print("❌ Error: Password cannot be empty. Please try again.")
                continue

            decrypt_choice = input("🗑️ Do you want to delete the encrypted file after decryption? (y/n): ").strip().lower()
            remove_encrypted = decrypt_choice == 'y'

            decrypt_file(encrypted_file_path, password, remove_encrypted)

        elif choice == '3':
            print("👋 Exiting the program. Goodbye!")
            sys.exit()

        else:
            print("❌ Invalid choice. Please select a valid option (1/2/3).")

if __name__ == "__main__":
    main()