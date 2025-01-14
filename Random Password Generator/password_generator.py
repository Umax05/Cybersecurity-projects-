# password_generator.py

import random
import string

def generate_password(length, use_uppercase, use_numbers, use_symbols):
    """Generate a random password based on the given criteria."""
    characters = string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one character type must be selected.")

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def get_user_input():
    """Prompt the user for password criteria and return the parameters."""
    while True:
        try:
            length = int(input("Enter the desired password length: "))
            if length <= 0:
                print("Password length must be a positive integer.")
                continue
            break
        except ValueError:
            print("Invalid input! Please enter a numerical value for length.")

    use_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
    use_numbers = input("Include numbers? (y/n): ").lower() == 'y'
    use_symbols = input("Include symbols? (y/n): ").lower() == 'y'

    if not (use_uppercase or use_numbers or use_symbols):
        print("No additional character types selected. Password will contain only lowercase letters.")

    return length, use_uppercase, use_numbers, use_symbols

def main():
    """Main function to run the Random Password Generator."""
    print("=== Random Password Generator ===")
    while True:
        length, use_uppercase, use_numbers, use_symbols = get_user_input()
        try:
            password = generate_password(length, use_uppercase, use_numbers, use_symbols)
            print(f"\nGenerated Password: {password}\n")
        except ValueError as ve:
            print(f"Error: {ve}\n")
            continue

        again = input("Generate another password? (y/n): ").lower()
        if again != 'y':
            print("Thank you for using the Random Password Generator. Goodbye!")
            break

if __name__ == "__main__":
    main()