from cryptography.fernet import Fernet
import os

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

if not os.path.exists('key.key'):
    write_key()

key = load_key()
fernet = Fernet(key)

def view_passwords():
    if not os.path.exists('passwords.txt'):
        print("No passwords have been saved yet.")
        return
    
    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            if data:
                account_name, encrypted_username, encrypted_password = data.split("|")
                username = fernet.decrypt(encrypted_username.encode()).decode()
                password = fernet.decrypt(encrypted_password.encode()).decode()
                print(f"Account: {account_name}\nUsername: {username}\nPassword: {password}\n")

def add_password():
    account_name = input("Account Name: ")
    username = input("Username: ")
    password = input("Password: ")

    encrypted_username = fernet.encrypt(username.encode()).decode()
    encrypted_password = fernet.encrypt(password.encode()).decode()

    with open('passwords.txt', 'a') as f:
        f.write(f"{account_name}|{encrypted_username}|{encrypted_password}\n")

def main():
    while True:
        mode = input("Would you like to add a new password or view existing ones (view/add)? Press 'q' to quit: ").lower()
        if mode == 'q':
            break
        elif mode == 'view':
            view_passwords()
        elif mode == 'add':
            add_password()
        else:
            print("Invalid mode.")

if __name__ == "__main__":
    main()