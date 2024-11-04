import requests
from checkpassword import check_password

def check_https(url):
    """Check if the URL uses HTTPS."""
    return url.startswith("https://")

def check_password_policy(password):
    """Check if the password meets security requirements."""
    is_strong, message = check_password(password)
    return is_strong, message  # Return both strength status and message

def attempt_login(url, username, password):
    """Attempt to log in with the provided username and password."""
    try:
        response = requests.post(url, data={'username': username, 'password': password})
        return response
    except requests.RequestException as e:
        print(f"Error during login attempt: {e}")
        return None

def check_account_lockout(url, username, max_attempts=5):
    """Check if the application implements account lockout mechanisms."""
    for _ in range(max_attempts):
        response = attempt_login(url, username, 'wrongpassword')  # Attempt with an invalid password
        if response is None:
            return False  # If the request failed, assume lockout cannot be determined

        # Check for lockout indication in the response
        if 'Too many attempts' in response.text:  # Adjust the message as needed
            return True  # Lockout mechanism is in place

    return False  # No lockout detected after max attempts

def check_password_storage(response):
    """Simulate checking for secure password storage."""
    return 'password' not in response.text

def check_credential_recovery(response):
    """Simulate checking for secure credential recovery."""
    return 'reset password' in response.text.lower()

def scan_website(url):
    """Perform security checks on the given URL."""
    results = {}

    # Check for HTTPS
    results['HTTPS'] = check_https(url)

    # Simulate a request to a login page
    try:
        response = requests.get(url)

        # Check password policy with a sample password
        sample_password = 'password'  # Placeholder for checking
        is_strong, password_message = check_password_policy(sample_password)
        results['Password Policy'] = not is_strong  # Invert for vulnerability
        results['Password Message'] = password_message  # Add the message about password strength
        results['Account Lockout'] = check_account_lockout(url, 'testuser')  # Replace 'testuser' with a valid username
        results['Insecure Password Storage'] = not check_password_storage(response)  # Invert for vulnerability
        results['Secure Credential Recovery'] = check_credential_recovery(response)

    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return None

    return results

def write_results_to_file(results, filename='auth_security_check_results.txt'):
    """Write the results to a specified file."""
    with open(filename, 'w') as file:
        file.write("Security Check Results:\n")
        for check, status in results.items():
            if check == 'Password Message':
                file.write(f"Password Policy: {status}\n")  # Include the password strength message
            else:
                file.write(f"{check}: {'Vulnerable' if status else 'Secure'}\n")

if __name__ == "__main__":
    target_url = input("Enter the target URL for login (e.g., http://example.com/login): ")
    results = scan_website(target_url)

    if results:
        write_results_to_file(results)  # Use the default file name
        print("Results written to auth_security_check_results.txt")
