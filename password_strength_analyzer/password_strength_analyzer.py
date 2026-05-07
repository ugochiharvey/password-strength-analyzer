"""
Password Strength Analyzer
Author: Ugochi Harvey

Evaluates the strength of the users inputter password based on specified
complexity rules and checks it against the list of commonly used passwords,
provided within a txt file
"""

import re # used to look for patterns
import secrets # used instead of random for safety
import string # helpful for data validation


def evaluate_complexity(password):
    """ Evaluates the passwords strength based on its
    length, casing use of numbers and symbols """
    password_complexity = 0

    if len(password) >= 8:
        password_complexity += 1

    if re.search(r"[A-Z]", password):
        password_complexity += 1

    if re.search(r"[a-z]", password):
        password_complexity += 1

    if re.search(r"\d", password):
        password_complexity += 1

    if re.search(r"[!@#$%^&*]", password):
        password_complexity += 1

    return password_complexity


def is_common_password(password, filename = "common_passwords.txt"):
    """ Checks to see if the inputted password is found in a
        provided file containing commonly used passwords"""
    try:
        with open(filename) as pswd_file:
            common = pswd_file.read().splitlines() # breaks multiline string into a list of their own lines
        return password in common
    
    # accounts for the file not existing, being misplaced or mispelled
    except FileNotFoundError:
        print(" ' ", filename, "' was not found: Unable to proceed with commonality check")
        return False

def generate_secure_password(length=16):
    """ Generates a secure random password """
    characters = (string.ascii_letters + string.digits + string.punctuation)
    return ''.join(secrets.choice(characters) for _ in range(length))

def main():
    """ Runs the password analyzer program """
    password = input("Enter password: ")
    is_secure = True

    password_complexity = evaluate_complexity(password)
    
    # categorizing the pswd_eval
    if password_complexity <= 2:
        print("Password is Weak")
        is_secure = False
        
    elif password_complexity <= 4:
        print("Password is Moderate")
        is_secure = False
    else:
        print("Password is strong!")

    # assessing commonality
    if is_common_password(password):
        print("Not a secure password, it is very common.")
        is_secure = False
        
    else:
        print("Password was not found on common password list!")

    # generates password if it is not secure
    if not is_secure:
        print("Here is a new secure generated password that can be used: ", generate_secure_password())

    else:
        # password is deemed secure
        print("Your password is ready to use!")

# runs when executed directly
if __name__ == "__main__":
    main()
