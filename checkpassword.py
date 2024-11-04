def check_password(password, output_file):
    """Check if the password meets security requirements and write results to the output file."""
    
    # Check length
    if len(password) < 8:
        with open(output_file, 'a') as f:  # Open in append mode
            f.write("Password: {} - Reason: Password must be at least 8 characters long.\n".format(password))
        return False, "Password must be at least 8 characters long."

    # Check for complexity
    if not (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?/' for c in password)):
        with open(output_file, 'a') as f:  # Open in append mode
            f.write("Password: {} - Reason: Password must contain upper and lower case letters, numbers, and special characters.\n".format(password))
        return False, "Password must contain upper and lower case letters, numbers, and special characters."

    # If the password is strong
    with open(output_file, 'a') as f:
        f.write("Password: {} - Result: Strong password.\n".format(password))
    return True, "Password is strong."

