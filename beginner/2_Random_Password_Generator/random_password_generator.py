import secrets
import string


def generate_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_special=True):
    """
    Generate a random password based on given parameters.

    Args:
        length (int): Length of the password.
        use_uppercase (bool): Include uppercase letters.
        use_lowercase (bool): Include lowercase letters.
        use_digits (bool): Include digits.
        use_special (bool): Include special characters.

    Returns:
        str: Generated password.
    """
    # Create character pool based on options
    character_pool = ""
    if use_uppercase:
        character_pool += string.ascii_uppercase
    if use_lowercase:
        character_pool += string.ascii_lowercase
    if use_digits:
        character_pool += string.digits
    if use_special:
        character_pool += string.punctuation

    if not character_pool:
        raise ValueError("You must select at least one character type to generate the password.")

    # Generate password
    password = ''.join(secrets.choice(character_pool) for _ in range(length))
    return password


def main():
    print("Welcome to the Secure Password Generator")
    # Ask user for password length
    while True:
        try:
            length = int(input("Enter the desired password length (minimum 8): "))
            if length < 8:
                print("The minimum length is 8 characters. Please try again.")
            else:
                break
        except ValueError:
            print("Please enter a valid number.")

    # Ask for inclusion options
    use_uppercase = input("Include uppercase letters? (y/n): ").strip().lower() == 'y'
    use_lowercase = input("Include lowercase letters? (y/n): ").strip().lower() == 'y'
    use_digits = input("Include digits? (y/n): ").strip().lower() == 'y'
    use_special = input("Include special characters? (y/n): ").strip().lower() == 'y'

    # Generate and show password
    try:
        password = generate_password(length, use_uppercase, use_lowercase, use_digits, use_special)
        print(f"Generated password: {password}")
    except ValueError as e:
        print(e)


if __name__ == "__main__":
    main()
