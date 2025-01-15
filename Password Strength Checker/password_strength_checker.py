# password_strength_checker.py

import re

def get_password():
    """
    Prompt the user to enter a password.
    """
    password = input("Enter your password to check its strength: ")
    return password

def check_length(password):
    """
    Check if the password length is at least 8 characters.
    """
    if len(password) >= 8:
        return True
    return False

def check_lowercase(password):
    """
    Check if the password contains at least one lowercase letter.
    """
    return bool(re.search(r'[a-z]', password))

def check_uppercase(password):
    """
    Check if the password contains at least one uppercase letter.
    """
    return bool(re.search(r'[A-Z]', password))

def check_digit(password):
    """
    Check if the password contains at least one digit.
    """
    return bool(re.search(r'\d', password))

def check_special_char(password):
    """
    Check if the password contains at least one special character.
    """
    return bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

def evaluate_password(password):
    """
    Evaluate the strength of the password based on various criteria.
    Returns a score and list of feedback messages.
    """
    score = 0
    feedback = []

    if check_length(password):
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    if check_lowercase(password):
        score += 1
    else:
        feedback.append("Include at least one lowercase letter.")

    if check_uppercase(password):
        score += 1
    else:
        feedback.append("Include at least one uppercase letter.")

    if check_digit(password):
        score += 1
    else:
        feedback.append("Include at least one digit.")

    if check_special_char(password):
        score += 1
    else:
        feedback.append("Include at least one special character (e.g., !, @, #, etc.).")

    return score, feedback

def display_results(score, feedback):
    """
    Display the results of the password evaluation.
    """
    print("\nPassword Strength Evaluation:")
    print(f"Score: {score}/5")

    if score == 5:
        print("Status: Strong Password 🔒✅")
    elif 3 <= score < 5:
        print("Status: Moderate Password ⚠️")
    else:
        print("Status: Weak Password ❌")

    if feedback:
        print("\nRecommendations to Improve Your Password:")
        for item in feedback:
            print(f"- {item}")

def password_strength_checker():
    """
    Main function to run the Password Strength Checker.
    """
    print("=== Password Strength Checker ===")
    password = get_password()
    score, feedback = evaluate_password(password)
    display_results(score, feedback)

if __name__ == "__main__":
    password_strength_checker()
