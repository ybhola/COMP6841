import re
import subprocess

# Define file paths
input_file_path = 'login.php'
output_file_path = 'login_fixed.php'

# Define vulnerable code pattern and secure replacement
vulnerable_code_pattern = r'\$sql\s*=\s*"SELECT \* FROM users WHERE username = \'(.*?)\' AND password = \'(.*?)\'";'
replacement_code = '''
// Prepare the SQL statement to prevent SQL injection
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $user, $pass);  // "ss" means both parameters are strings
$stmt->execute();
$result = $stmt->get_result();
'''

# Step 1: Scan for vulnerabilities using semgrep
def scan_for_sql_injection(file_path):
    print("Scanning for SQL injection vulnerabilities...")
    result = subprocess.run(
        ['semgrep', '--config', 'p/php.lang.security.sql_injection', file_path],
        stdout=subprocess.PIPE, text=True
    )
    output = result.stdout
    print("Scan Results:\n", output)

    # Extract vulnerable lines (for demonstration purposes; in real use, semgrep output parsing is needed)
    vulnerable_lines = []
    for line in output.splitlines():
        if "pattern" in line:
            vulnerable_lines.append(line)

    return vulnerable_lines

# Step 2: Fix the vulnerable code
def fix_vulnerable_code(file_path, output_path, pattern, replacement):
    with open(file_path, 'r') as file:
        code = file.read()

    # Search for and replace vulnerable code
    new_code = re.sub(pattern, replacement, code)

    # Write the fixed code to a new file
    with open(output_path, 'w') as file:
        file.write(new_code)

    print(f"Vulnerabilities have been fixed and saved to {output_path}")

# Run the scan and fix process
vulnerable_lines = scan_for_sql_injection(input_file_path)
print("Vulnerable Lines Found:\n", vulnerable_lines)

# Apply the fix
fix_vulnerable_code(input_file_path, output_file_path, vulnerable_code_pattern, replacement_code)
